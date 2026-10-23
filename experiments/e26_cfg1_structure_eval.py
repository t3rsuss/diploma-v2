"""Оцінювання меж і ролей CFG1; спільне відновлення, не held-out."""
import csv
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import analyze_all as A
from demo import cfg1


def normalize(fields):
    out = []
    for a, b, role in sorted(fields):
        if (
            out and role == "константа"
            and out[-1][2] == role and out[-1][1] == a
        ):
            out[-1] = (out[-1][0], b, role)
        else:
            out.append((a, b, role))
    return out


def boundaries(fields, size):
    return {
        x for a, b, _ in fields for x in (a, b)
        if 0 < x < size
    }


def scores(tp, predicted, expected):
    precision = tp / predicted if predicted else 0.0
    recall = tp / expected if expected else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0.0
    )
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def main():
    folder = ROOT / "demo" / "samples_cfg1"
    paths = sorted(folder.glob("*.cfg"))
    if len(paths) < 5:
        raise SystemExit("Need at least 5 existing CFG1 files; nothing generated.")

    samples, truths = [], []
    for path in paths:
        data = path.read_bytes()
        log = A.RB._trace_custom(cfg1.parse_file, data)
        samples.append((data, log))
        truths.append(normalize(cfg1.truth_fields(data)))

    inferred = A.RB.INF2.infer2(samples)
    if len(inferred) != len(samples):
        raise RuntimeError("Inference result count does not match input count")

    rows, errors = [], []
    totals = {}

    for path, (data, log), truth, prediction in zip(
        paths, samples, truths, inferred
    ):
        methods = {
            "read_intervals": [
                (p, p + length, None)
                for p, length, _ in A.RB.INF2.prune(log)
            ],
            "infer2": normalize(prediction),
        }
        true_boundaries = boundaries(truth, len(data))
        true_intervals = {(a, b) for a, b, _ in truth}
        true_roles = set(truth)

        for method, fields in methods.items():
            predicted_boundaries = boundaries(fields, len(data))
            predicted_intervals = {(a, b) for a, b, _ in fields}
            comparisons = {
                "boundary": (predicted_boundaries, true_boundaries),
                "interval": (predicted_intervals, true_intervals),
            }
            if method == "infer2":
                comparisons["interval_role"] = (set(fields), true_roles)

            for metric, (predicted, expected) in comparisons.items():
                tp = len(predicted & expected)
                counts = (tp, len(predicted), len(expected))
                key = (method, metric)
                total = totals.setdefault(key, [0, 0, 0])
                for i, value in enumerate(counts):
                    total[i] += value
                rows.append({
                    "file": path.name,
                    "method": method,
                    "metric": metric,
                    "tp": tp,
                    "predicted": len(predicted),
                    "expected": len(expected),
                    **scores(*counts),
                })

            if method == "infer2":
                errors.append({
                    "file": path.name,
                    "missing_or_wrong_role": [
                        list(x) for x in sorted(true_roles - set(fields))
                    ],
                    "extra_or_wrong_role": [
                        list(x) for x in sorted(set(fields) - true_roles)
                    ],
                })

    output = ROOT / "results"
    output.mkdir(parents=True, exist_ok=True)

    with (output / "cfg1_structure_eval.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    summary = {
        "mode": "joint_sample_inference",
        "files": len(paths),
        "normalization": "Merge adjacent constant fields only.",
        "limitations": [
            "Synthetic CFG1 with a purpose-built reader.",
            "All evaluated files participate in inference.",
            "No held-out generalization claim.",
            "Reader boundaries provide structural information.",
            "Role scores require both exact interval and exact role.",
        ],
        "metrics": [],
    }

    print(f"Files: {len(paths)}; joint inference; adjacent constants merged")
    print(f"{'method':18s} {'metric':15s} {'P':>8s} {'R':>8s} {'F1':>8s}")
    for (method, metric), counts in sorted(totals.items()):
        result = scores(*counts)
        summary["metrics"].append({
            "method": method,
            "metric": metric,
            "tp": counts[0],
            "predicted": counts[1],
            "expected": counts[2],
            **result,
        })
        print(
            f"{method:18s} {metric:15s} "
            f"{result['precision']:8.3f} "
            f"{result['recall']:8.3f} "
            f"{result['f1']:8.3f}"
        )

    (output / "cfg1_structure_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8",
    )
    (output / "cfg1_structure_errors.json").write_text(
        json.dumps(errors, ensure_ascii=False, indent=2), encoding="utf-8",
    )
    print("Saved: per-file CSV, summary JSON, field errors JSON")


if __name__ == "__main__":
    main()
