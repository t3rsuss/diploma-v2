"""Пояснення гіпотез довжин за фактичною роботою читача."""
import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import analyze_all as A
from length_evidence import explain_lengths

INF = A.RB.INF2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", required=True)
    parser.add_argument("--reader", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()

    if args.limit < 5:
        parser.error("--limit must be at least 5")

    folder = pathlib.Path(args.samples)
    if not folder.is_dir():
        parser.error("--samples must be an existing directory")

    paths = sorted(
        path for path in folder.iterdir()
        if path.is_file() and 16 <= path.stat().st_size <= 300_000
    )[:args.limit]

    if len(paths) < 5:
        raise SystemExit("Need at least 5 files of size 16..300000 bytes.")

    reader = A.RB.load_reader(args.reader)
    samples = []
    for path in paths:
        data = path.read_bytes()
        log = A.RB._trace_custom(reader, data)
        samples.append((data, log))

    inferred = INF.infer2(samples)
    evidence = explain_lengths(samples)[0]

    fields = [
        {"start": a, "end": b, "role": role}
        for a, b, role in inferred[0]
    ]
    payload = {
        "mode": "joint_sample_inference",
        "reader": args.reader,
        "sample_count": len(paths),
        "example_file": paths[0].name,
        "fields": fields,
        "length_evidence": evidence,
        "limitations": [
            "Support is a fraction of matching read events, not a probability.",
            "The same sample set is used to select and explain rules.",
            "Numeric matches do not prove the semantic role of a field.",
            "Adjacent zero bytes can make field width ambiguous.",
            "This report explains length rules, not every inferred role.",
        ],
    }

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"Samples: {len(paths)}; example: {paths[0].name}")
    print("\nSTRUCTURE")
    for field in fields[:20]:
        print(
            f"{field['start']:6d}..{field['end']:<6d} "
            f"{field['role']}"
        )

    print("\nLENGTH HYPOTHESES")
    for item in evidence[:12]:
        a, b = item["field"]
        target = item["related_interval"]
        target_text = (
            f"{target[0]}..{target[1]}" if target is not None else "NO MATCH"
        )
        print(
            f"Field {a}..{b}: value={item['value']}; "
            f"encoding={item['encoding']}; related={target_text}"
        )
        print(
            f"  Matching events: {item['matching_events']}/"
            f"{item['checked_events']}; "
            f"files with matches: {item['files_with_matching_events']}; "
            f"distinct values: {item['distinct_values']}"
        )
        print(f"  Reader context: {item['context']}")
        print(f"  Status: {item['interpretation']}")

    print(f"\nSaved: {out}")


if __name__ == "__main__":
    main()
