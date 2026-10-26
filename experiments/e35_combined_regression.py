import collections
import hashlib
import json
import pathlib
import random
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import rebin as RB
import e34_combined_lengths as V3
import trace_lib as T
from demo import cfg1, xdt3, evtx_reader
from experiments.e26_cfg1_structure_eval import normalize

OUT = ROOT / "results/e35_combined_regression.json"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compare(name, paths, reader, truth=None, norm=None, limit=30,
            min_size=0, max_size=None, max_events=None):
    items, selected, skipped = [], [], []

    for path in paths:
        if len(items) >= limit:
            break
        try:
            if not path.is_file():
                continue
            size = path.stat().st_size
            if size < min_size or (max_size is not None and size > max_size):
                continue
            data = path.read_bytes()
            log = reader(data)
            if not log or (max_events is not None and len(log) > max_events):
                raise ValueError("Empty trace or event limit exceeded")
            expected = truth(data) if truth else None
        except Exception as exc:
            skipped.append({
                "file": str(path.relative_to(ROOT)),
                "error": type(exc).__name__ + ": " + str(exc),
            })
            continue
        items.append((data, log, expected))
        selected.append(path)

    print("\nDATASET:", name, "| accepted:", len(items),
          "| skipped/errors:", len(skipped), flush=True)

    result = {
        "dataset": name,
        "files": len(items),
        "skipped": skipped,
        "inputs": [
            {"file": str(p.relative_to(ROOT)), "sha256": sha(p)}
            for p in selected
        ],
    }
    if len(items) < 5:
        result["status"] = "insufficient_files"
        print("NOT EVALUATED: need at least 5 accepted files", flush=True)
        return result

    samples = [(data, log) for data, log, _ in items]
    old = RB.INF2.infer2(samples)
    new = V3.infer2(samples)
    assert len(old) == len(new) == len(items)

    changes = collections.Counter()
    interval_difference = 0
    changed_files = []
    lost_correct, gained_correct = [], []

    for path, (_, _, expected), fa, fb in zip(selected, items, old, new):
        a = {(s, e): role for s, e, role in fa}
        b = {(s, e): role for s, e, role in fb}
        interval_difference += len(set(a) ^ set(b))
        file_changes = []
        for iv in sorted(set(a) | set(b)):
            if a.get(iv) != b.get(iv):
                changes[(a.get(iv), b.get(iv))] += 1
                file_changes.append({
                    "interval": list(iv),
                    "from": a.get(iv),
                    "to": b.get(iv),
                })
        if file_changes:
            changed_files.append({
                "file": path.name,
                "changes": file_changes,
            })

        if expected is not None:
            transform = norm or (lambda fields: fields)
            correct = {tuple(x) for x in transform(expected)}
            pa = {tuple(x) for x in transform(fa)}
            pb = {tuple(x) for x in transform(fb)}
            for field in sorted((pa & correct) - pb):
                lost_correct.append({"file": path.name, "field": list(field)})
            for field in sorted((pb & correct) - pa):
                gained_correct.append({"file": path.name, "field": list(field)})

    result.update({
        "status": "evaluated",
        "interval_symmetric_difference_count": interval_difference,
        "role_changes": [
            {"from": a, "to": b, "count": n}
            for (a, b), n in changes.items()
        ],
        "changed_files": changed_files,
        "truth_available": truth is not None,
        "lost_exact_correct_fields": lost_correct,
        "gained_exact_correct_fields": gained_correct,
        "anchored_rules": list(V3.ANCHORED_RULES),
        "new_rules": [
            {"key": list(k), "excluded_values": sorted(v)}
            for k, v in V3.MARKER_VALUES.items()
        ],
    })

    print("Interval differences:", interval_difference)
    print("Role changes:", result["role_changes"])
    print("New rules:", result["new_rules"])
    print("Anchored rules:", result["anchored_rules"])
    if truth:
        print("Lost exact correct fields:", len(lost_correct))
        print("Gained exact correct fields:", len(gained_correct))
    else:
        print("Semantic correctness not assessed; comparison with v2 only")
    return result


def main():
    results = []
    files = T.collect_files()
    rng = random.Random(42)

    for fmt in ("png", "gif", "ico", "wav", "gz", "docx"):
        paths = sorted(files.get(fmt, []))
        rng.shuffle(paths)
        results.append(compare(
            fmt, paths,
            lambda data, fmt=fmt: RB.CTX.run_ctx(fmt, data),
            min_size=1024, max_size=150_000, max_events=3000,
        ))

    results.append(compare(
        "cfg1",
        sorted((ROOT / "demo/samples_cfg1").glob("*.cfg")),
        lambda data: RB._trace_custom(cfg1.parse_file, data),
        truth=cfg1.truth_fields, norm=normalize, limit=1000,
    ))

    results.append(compare(
        "xdt3",
        sorted(p for p in (ROOT / "demo/samples_xdt3").glob("*") if p.is_file()),
        lambda data: RB._trace_custom(xdt3.parse_file, data),
        truth=xdt3.truth_fields, limit=1000,
    ))

    results.append(compare(
        "evtx",
        sorted((ROOT / "data/corpus/evtx").glob("*.evtx")),
        lambda data: RB._trace_custom(evtx_reader.parse_head, data),
        limit=1000,
    ))

    report = {
        "scope": (
            "Development/regression only. No held-out captures. "
            "Real-format comparison tests output stability, not semantic truth. "
            "CFG1 truth comparison merges adjacent constants; XDT3 uses raw fields."
        ),
        "commit": subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT,
            capture_output=True, text=True, check=True,
        ).stdout.strip(),
        "code_sha256": {
            p: sha(ROOT / p) for p in (
                "experiments/e20_infer2.py",
                "experiments/e30_local_markers.py",
                "experiments/e34_combined_lengths.py",
                "experiments/e35_combined_regression.py",
                "experiments/e18_context.py",
                "rebin.py",
                "demo/cfg1.py",
                "demo/xdt3.py",
                "demo/evtx_reader.py",
                "experiments/e26_cfg1_structure_eval.py",
            )
        },
        "datasets": results,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print("\nSaved:", OUT)


if __name__ == "__main__":
    main()
