import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    from rebin import analyze
    from demo import xdt2
    from demo.eval_xdt import aggregate, evaluate_file, truth_fields
    from demo.make_xdt_samples import main as generate_xdt1

    generate_xdt1()
    sets = [
        ("XDT1", ROOT / "demo" / "samples_xdt1", "demo.xdt_reader:parse_file", truth_fields),
        ("XDT2", xdt2.generate(), "demo.xdt2:parse_file", xdt2.truth_fields),
    ]

    table, lines = [], [
        f"{'формат':8s}{'алгоритм':10s}{'точність':>10s}{'повнота':>10s}{'F1':>8s}{'байти, роль':>13s}",
    ]
    for name, folder, reader, truth in sets:
        for engine in ("v1", "v2"):
            report = analyze([str(folder)], reader=reader, limit=20, engine=engine)
            results = []
            for item in report["all_fields"]:
                data = (folder / item["file"]).read_bytes()
                pred = [tuple(x) for x in item["fields"]]
                results.append(evaluate_file(pred, truth(data), len(data)))
            s = aggregate(results)
            table.append({"format": name, "engine": engine, **s})
            lines.append(
                f"{name:8s}{engine:10s}{100 * s['boundary_precision']:9.1f}%"
                f"{100 * s['boundary_recall']:9.1f}%{s['boundary_f1']:8.3f}"
                f"{100 * s['role_byte_accuracy']:12.1f}%"
            )

    text = "\n".join(lines)
    print(text)
    out = ROOT / "results"
    out.mkdir(exist_ok=True)
    (out / "eval_compare.txt").write_text(text + "\n", encoding="utf-8")
    (out / "eval_compare.json").write_text(
        json.dumps(table, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print("\nSaved: results/eval_compare.txt, results/eval_compare.json")


if __name__ == "__main__":
    main()
