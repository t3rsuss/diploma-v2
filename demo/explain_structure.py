"""Пояснення гіпотез довжин за фактичною роботою читача."""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import analyze_all as A

INF = A.RB.INF2


def main():
    paths = sorted((ROOT / "demo/samples_xdt3").glob("*.xd3"))
    if len(paths) < 5:
        raise SystemExit("Need at least 5 existing XDT3 samples.")

    reader = A.RB.load_reader("demo.xdt3:parse_file")
    samples = []
    for path in paths:
        data = path.read_bytes()
        log = A.RB._trace_custom(reader, data)
        samples.append((data, log))

    merged = INF.merge_runs(samples)
    rules = INF.learn_rules(merged)
    inferred = INF.infer2(samples)

    evidence = []
    data, log = merged[0]

    for index, (pos, length, context) in enumerate(log):
        for offset, width, order, _ in rules.get((context, length), ()):
            value = INF.read_value(data, pos, offset, width, order)
            start, sums, singles = INF.following(
                log, index, pos + length,
            )

            target = None
            relation = "no_match_in_this_file"
            if value is not None and value >= INF.MIN_VAL:
                if value in sums:
                    target = [start, start + value]
                    relation = "following_contiguous_reads"
                else:
                    for p, size in singles:
                        if size == value:
                            target = [p, p + size]
                            relation = "nearby_single_read"
                            break

            occurrences = matches = 0
            matched_files = set()
            values = set()

            for file_index, (raw, events) in enumerate(merged):
                for i, (p, size, ctx) in enumerate(events):
                    if (ctx, size) != (context, length):
                        continue
                    v = INF.read_value(raw, p, offset, width, order)
                    _, totals, separate = INF.following(events, i, p + size)
                    occurrences += 1
                    if v is not None:
                        values.add(v)
                    if (
                        v is not None
                        and v >= INF.MIN_VAL
                        and (v in totals or any(n == v for _, n in separate))
                    ):
                        matches += 1
                        matched_files.add(file_index)

            evidence.append({
                "field": [pos + offset, pos + offset + width],
                "hypothesis": "length",
                "context": context,
                "encoding": order,
                "width_bytes": width,
                "value": value,
                "related_interval": target,
                "relation": relation,
                "local_read_match": target is not None,
                "interpretation": (
                    "Гіпотеза за вибіркою; є числовий збіг із читаннями цього файла."
                    if target is not None else
                    "Гіпотеза за вибіркою; збігу з читаннями цього файла не знайдено."
                ),
                "matching_events": matches,
                "checked_events": occurrences,
                "event_support": matches / occurrences if occurrences else 0.0,
                "files_with_matching_events": len(matched_files),
                "distinct_values": len(values),
            })

    fields = [
        {"start": a, "end": b, "role": role}
        for a, b, role in inferred[0]
    ]
    payload = {
        "mode": "joint_sample_inference",
        "reader": "demo.xdt3:parse_file",
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

    out = ROOT / "results/structure_explanation_xdt3.json"
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

    print(f"\nSaved: {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
