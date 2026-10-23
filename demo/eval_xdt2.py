import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    from rebin import analyze
    from demo import xdt2
    from demo.eval_xdt import aggregate, evaluate_file, render

    samples = xdt2.generate()
    report = analyze([str(samples)], reader="demo.xdt2:parse_file", limit=20)

    results = []
    for item in report["all_fields"]:
        data = (samples / item["file"]).read_bytes()
        pred = [tuple(x) for x in item["fields"]]
        results.append(evaluate_file(pred, xdt2.truth_fields(data), len(data)))

    summary = aggregate(results)
    text = render(summary)
    print(text)

    out = ROOT / "results"
    out.mkdir(exist_ok=True)
    (out / "eval_xdt2_firstrun.txt").write_text(text + "\n", encoding="utf-8")
    (out / "eval_xdt2_firstrun.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print("\nSaved: results/eval_xdt2_firstrun.txt, results/eval_xdt2_firstrun.json")


if __name__ == "__main__":
    main()
