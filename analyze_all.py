"""Спільний звіт: гіпотези структури, індикатори у блоках і непрочитаних ділянках."""
import argparse
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments"))

import rebin as RB
from block_scan import scan_file
from recovery_audit import audit_intervals
from threat_scan import scan as scan_unread

BLOCK_RANK = {"низький": 1, "середній": 2, "високий": 3}
UNREAD_RANK = {"low": 0, "mid": 2, "high": 3}
LEVELS = ["індикаторів не виявлено", "інформаційний", "підозрілий", "високий"]



def block_rank(finding):
    if finding["kind"] == "блок з високою ентропією":
        return 1
    return BLOCK_RANK[finding["severity"]]



def audit_event(audit, path, stage, status, reason=None):
    entry = {
        "file": path.name,
        "path": str(path.resolve()),
        "stage": stage,
        "status": status,
    }
    if reason is not None:
        entry["reason"] = reason
    audit.append(entry)


def collect_with_audit(paths, limit, audit, seed=42):
    import random

    files = []
    for path in map(pathlib.Path, paths):
        try:
            if path.is_dir():
                files.extend(x for x in path.rglob("*") if x.is_file())
            else:
                files.append(path)
        except OSError as exc:
            audit_event(
                audit, path, "collection", "rejected",
                f"{type(exc).__name__}: {exc}",
            )

    files = sorted(set(files))
    random.Random(seed).shuffle(files)
    selected = []

    for path in files:
        try:
            size = path.stat().st_size
        except OSError as exc:
            audit_event(
                audit, path, "collection", "rejected",
                f"{type(exc).__name__}: {exc}",
            )
            continue

        if not 16 <= size <= 300_000:
            audit_event(
                audit, path, "collection", "rejected",
                f"Supported file size: 16..300000 bytes; got {size}",
            )
        elif len(selected) >= limit:
            audit_event(
                audit, path, "collection", "skipped", "candidate_limit",
            )
        else:
            selected.append(path)
            audit_event(audit, path, "collection", "selected")

    return selected


def analyze_set(sample_paths, targets=(), fmt=None, reader=None, limit=40, sample_audit=None):
    if bool(fmt) == bool(reader):
        raise ValueError("Specify exactly one of format or reader")
    if limit < 5:
        raise ValueError("Sample limit must be at least 5")

    audit = [] if sample_audit is None else sample_audit
    func = RB.load_reader(reader) if reader else None
    target_paths = {pathlib.Path(p).resolve() for p in targets}
    samples = collect_with_audit(sample_paths, limit * 3, audit)
    paths = sorted(target_paths) + [
        pathlib.Path(p).resolve() for p in samples
        if pathlib.Path(p).resolve() not in target_paths
    ]

    items, reports, used_samples = [], [], 0
    for path in paths:
        if path not in target_paths and used_samples >= limit:
            audit_event(audit, path, "reading", "skipped", "sample_limit")
            continue
        try:
            if not 16 <= path.stat().st_size <= 300_000:
                raise ValueError("Supported file size: 16..300000 bytes")
            data = path.read_bytes()
            if not 16 <= len(data) <= 300_000:
                raise ValueError("Supported file size: 16..300000 bytes")
            log = (
                RB._trace_custom(func, data)
                if func else RB.CTX.run_ctx(fmt, data)
            )
            if not log:
                raise ValueError("Reader produced no read events")
        except Exception as exc:
            audit_event(
                audit, path, "reading", "rejected",
                f"{type(exc).__name__}: {exc}",
            )
            reports.append({
                "file": path.name,
                "path": str(path),
                "status": "error",
                "risk": "не оцінено",
                "error": f"{type(exc).__name__}: {exc}",
            })
            continue

        audit_event(audit, path, "reading", "accepted")
        items.append((path, data, log))
        if path not in target_paths:
            used_samples += 1

    if len(items) < 5:
        raise ValueError(
            f"Need at least 5 readable files; got {len(items)}. Errors: {reports}"
        )

    inferred = RB.INF2.infer2([(data, log) for _, data, log in items])
    if len(inferred) != len(items):
        raise ValueError(
            f"Inference result count mismatch: expected {len(items)}, "
            f"got {len(inferred)}"
        )
    for path, _, _ in items:
        audit_event(audit, path, "inference", "used")

    for (path, data, log), fields in zip(items, inferred):
        if target_paths and path not in target_paths:
            continue

        blocks = scan_file(data, fields)
        unread = scan_unread(data, log)
        rank = max(
            [block_rank(f) for f in blocks]
            + [UNREAD_RANK[unread["level"]]]
        )

        reports.append({
            "file": path.name,
            "path": str(path),
            "status": "ok",
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "risk": LEVELS[rank],
            "fields": [
                {
                    "start": a,
                    "end": b,
                    "size": b - a,
                    "role": role,
                    "context": RB.label_for(a, b, log),
                    "hex": data[a:min(b, a + 8)].hex(),
                }
                for a, b, role in fields
            ],
            "interval_audit": audit_intervals(
                [(a, b) for a, b, _ in fields], len(data)
            ),
            "block_findings": blocks,
            "unread_scan": unread,
        })

    if target_paths:
        reports = [
            r for r in reports
            if pathlib.Path(r["path"]) in target_paths
        ]
    return reports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", nargs="+", required=True)
    parser.add_argument("--target", nargs="*", default=[])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--format", choices=["png", "gif", "ico", "wav", "gz", "docx"])
    source.add_argument("--reader")
    parser.add_argument("--limit", type=int, default=40)
    parser.add_argument("--out", default="results/analysis_report.json")
    args = parser.parse_args()

    sample_audit = []
    run_error = None
    try:
        reports = analyze_set(
            args.samples, args.target, args.format, args.reader,
            args.limit, sample_audit=sample_audit,
        )
    except ValueError as exc:
        reports = []
        run_error = f"{type(exc).__name__}: {exc}"
    for report in reports:
        print(
            f"{report['file']:28s} {report['status']:6s} "
            f"{report['risk']} {report.get('error', '')}"
        )

    output = pathlib.Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps({
            "schema_version": 2,
            "run_status": "error" if run_error else "ok",
            "run_error": run_error,
            "sample_audit": sample_audit,
            "risk_policy": "v2_entropy_in_read_blocks_is_informational",
            "mode": "joint_sample_inference",
            "limitations": [
                "Targets participate in structure inference; this is not held-out evaluation.",
                "Risk levels are heuristic indicators, not malware verdicts.",
                "PE/ELF header matches do not validate a complete executable.",
                "High entropy alone does not prove encryption or maliciousness.",
            ],
            "reports": reports,
        }, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print("Saved:", output)
    if run_error:
        print(run_error, file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
