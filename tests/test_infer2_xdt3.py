from demo import xdt3
from demo.eval_xdt import aggregate, evaluate_file
from rebin import analyze


def test_v2_xdt3_regression_floor():
    folder = xdt3.generate()
    report = analyze([str(folder)], reader="demo.xdt3:parse_file", limit=20, engine="v2")
    results = []
    for item in report["all_fields"]:
        data = (folder / item["file"]).read_bytes()
        pred = [tuple(x) for x in item["fields"]]
        results.append(evaluate_file(pred, xdt3.truth_fields(data), len(data)))
    s = aggregate(results)
    assert s["boundary_f1"] >= 0.90
    lengths = s["by_role"]["довжина"]
    assert lengths["exact_correct"] == lengths["total"]
