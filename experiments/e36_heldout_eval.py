"""Frozen-code joint inference on previously reserved captures."""
import ast
import collections
import hashlib
import importlib.util
import io
import json
import pathlib
import platform
import struct
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import rebin as RB
import e34_combined_lengths as NEW
from demo import dns_reader, pcapng_reader, pcapng_truth

LEN = "\u0434\u043e\u0432\u0436\u0438\u043d\u0430"
OUT = ROOT / "results/e36_heldout_eval.json"
CODE = [
    "experiments/e36_heldout_eval.py",
    "experiments/e20_infer2.py",
    "experiments/e30_local_markers.py",
    "experiments/e34_combined_lengths.py",
    "experiments/e18_context.py",
    "experiments/extract_dns_from_pcapng.py",
    "experiments/e28_dns_structure_eval.py",
    "demo/dns_reader.py",
    "demo/pcapng_reader.py",
    "demo/pcapng_truth.py",
    "rebin.py",
    "recovery_audit.py",
    "results/heldout_manifest.json",
    "docs/v3_criteria.md",
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(*args):
    return subprocess.run(
        ["git", *args], cwd=ROOT,
        capture_output=True, text=True, check=True,
    ).stdout.strip()


def load_dns_truth():
    source = ROOT / "experiments/e28_dns_structure_eval.py"
    tree = ast.parse(source.read_text(encoding="utf-8-sig"))
    nodes = [
        n for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "truth"
    ]
    assert len(nodes) == 1
    namespace = {"struct": struct}
    exec(
        compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"),
        namespace,
    )
    return namespace["truth"]


def evaluate(items, length_kinds, expected_blocks=None):
    samples = [(item["data"], item["log"]) for item in items]
    results = {}

    for version, engine in (("v2", RB.INF2), ("combined", NEW)):
        started = time.perf_counter()
        output = engine.infer2(samples)
        seconds = time.perf_counter() - started
        assert len(output) == len(items)

        counts = collections.defaultdict(collections.Counter)
        true_lengths = found_lengths = missing = total = false_count = 0
        false_examples = []

        for item, fields in zip(items, output):
            predicted = {(a, b): role for a, b, role in fields}
            valid = {
                (a, b) for a, b, kind in item["truth"]
                if kind in length_kinds
            }
            true_lengths += len(valid)
            found_lengths += sum(predicted.get(iv) == LEN for iv in valid)

            for a, b, kind in item["truth"]:
                total += 1
                missing += (a, b) not in predicted
                counts[kind][predicted.get((a, b), "no exact interval")] += 1

            for a, b, role in fields:
                if role == LEN and (a, b) not in valid:
                    false_count += 1
                    if len(false_examples) < 20:
                        false_examples.append({
                            "input": item["name"], "interval": [a, b],
                        })

        result = {
            "seconds": seconds,
            "true_length_fields": true_lengths,
            "correct_length_labels": found_lengths,
            "length_recall": (
                found_lengths / true_lengths if true_lengths else None
            ),
            "false_length_labels": false_count,
            "false_length_examples": false_examples,
            "true_intervals": total,
            "missing_exact_intervals": missing,
            "exact_interval_recall": (
                (total - missing) / total if total else None
            ),
            "roles_by_field": {k: dict(v) for k, v in counts.items()},
        }

        if version == "combined" and expected_blocks is not None:
            discovered = {
                (e["file_index"], *e["field"], *e["block"])
                for e in NEW.ANCHORED_EVIDENCE
            }
            result["anchored_blocks"] = {
                "expected": len(expected_blocks),
                "correct": len(discovered & expected_blocks),
                "incorrect": len(discovered - expected_blocks),
                "missing": len(expected_blocks - discovered),
            }
            result["anchored_rules"] = list(NEW.ANCHORED_RULES)

        results[version] = result
    return results


def main():
    assert not OUT.exists(), "Result exists; refusing to overwrite"
    dirty = git("status", "--porcelain", "--", *CODE)
    assert not dirty, "Commit evaluation code and dependencies first:\n" + dirty
    hashes = {name: digest((ROOT / name).read_bytes()) for name in CODE}

    manifest = json.loads(
        (ROOT / "results/heldout_manifest.json").read_text(encoding="utf-8")
    )
    folder = ROOT / "data/corpus/pcapng_heldout"
    rows = manifest["files"]
    assert len(rows) == 12
    assert {p.name for p in folder.glob("*.pcapng")} == {
        row["name"] for row in rows
    }
    assert digest(
        "".join(row["sha256"] for row in rows).encode()
    ) == manifest["set_sha256"]

    captures = []
    for row in rows:
        raw = (folder / row["name"]).read_bytes()
        assert len(raw) == row["bytes"], "Size mismatch: " + row["name"]
        assert digest(raw) == row["sha256"], "Hash mismatch: " + row["name"]
        captures.append((row["name"], raw))

    spec = importlib.util.spec_from_file_location(
        "capture_extractor",
        ROOT / "experiments/extract_dns_from_pcapng.py",
    )
    extractor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(extractor)
    dns_truth = load_dns_truth()

    development = {
        p.read_bytes()
        for p in (ROOT / "data/corpus/dns").glob("*.dns")
    }
    assert development, "Development DNS corpus unavailable for overlap check"

    unique_dns = set()
    pcap_items, expected_blocks = [], set()

    for name, raw in captures:
        stream = io.BytesIO(raw)
        pcapng_reader.parse_file(stream)
        assert stream.tell() == len(raw)
        fields, blocks = pcapng_truth.truth(raw)
        index = len(pcap_items)
        pcap_items.append({
            "name": name, "data": raw, "truth": fields,
            "log": RB._trace_custom(pcapng_reader.parse_file, raw),
        })
        for block in blocks:
            expected_blocks.add((
                index, *block["length_field"], block["start"], block["end"],
            ))

        for frame in extractor.frames(raw):
            payload = extractor.dns_payload(frame)
            if payload is not None:
                unique_dns.add(payload)

    overlap = unique_dns & development
    dns_items, rejected = [], []
    for raw in sorted(unique_dns - development):
        name = digest(raw)
        try:
            stream = io.BytesIO(raw)
            dns_reader.parse_file(stream)
            assert stream.tell() == len(raw)
            fields = dns_truth(raw)
            assert fields and fields[-1][1] == len(raw)
            log = RB._trace_custom(dns_reader.parse_file, raw)
        except Exception as exc:
            rejected.append({
                "sha256": name,
                "error": type(exc).__name__ + ": " + str(exc),
            })
            continue
        dns_items.append({
            "name": name, "data": raw, "truth": fields, "log": log,
        })

    assert len(dns_items) >= 5, "Insufficient accepted DNS messages"

    report = {
        "scope": (
            "Frozen-code evaluation on reserved captures. Joint/transductive "
            "inference within each evaluation set, not a pretrained model. "
            "DNS and pcapng are two views of the same captures, not independent sets."
        ),
        "limitations": [
            "Author-written readers and truth annotations.",
            "Reader boundaries provide structural information.",
            "DNS extraction reuses the limited development extractor: UDP only; "
            "not a full IP reassembly or IPv6 extension-header implementation.",
            "DNS duplicates are removed by exact bytes, not transaction identity.",
            "pcapng annotation covers the block envelope, not packet semantics.",
            "Failure during capture parsing aborts the run rather than silently "
            "removing a capture.",
            "v2 related-block intervals are not evaluated; anchored-block "
            "metrics apply only to the combined mechanism.",
        ],
        "commit": git("rev-parse", "HEAD"),
        "python": platform.python_version(),
        "code_sha256": hashes,
        "manifest_set_sha256": manifest["set_sha256"],
        "development_dns_set_sha256": digest(
            "".join(sorted(digest(d) for d in development)).encode()
        ),
        "captures": len(captures),
        "dns_selection": {
            "unique_extracted": len(unique_dns),
            "exact_development_overlap_removed": len(overlap),
            "accepted": len(dns_items),
            "rejected": rejected,
            "accepted_sha256": [x["name"] for x in dns_items],
        },
        "dns": evaluate(
            dns_items, {"qname_len", "rr_len", "rr_rdlen"},
        ),
        "pcapng": evaluate(
            pcap_items, {"block_length", "block_length_repeat"},
            expected_blocks,
        ),
    }

    assert hashes == {
        name: digest((ROOT / name).read_bytes()) for name in CODE
    }, "A dependency changed during evaluation"

    OUT.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8",
    )

    print("Captures:", report["captures"])
    print("DNS selection:", {
        k: v for k, v in report["dns_selection"].items()
        if k != "accepted_sha256"
    })
    for dataset in ("dns", "pcapng"):
        print("\nDATASET:", dataset)
        for version, result in report[dataset].items():
            print(version)
            print("  lengths:", result["correct_length_labels"],
                  "/", result["true_length_fields"])
            print("  false length labels:", result["false_length_labels"])
            print("  missing exact intervals:", result["missing_exact_intervals"])
            print("  roles by field:", result["roles_by_field"])
            if "anchored_blocks" in result:
                print("  anchored blocks:", result["anchored_blocks"])
    print("\nSaved:", OUT)


if __name__ == "__main__":
    main()
