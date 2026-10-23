from demo import xdt2
from demo.eval_xdt import aggregate, evaluate_file
from rebin import analyze


def run(engine):
    folder = xdt2.generate()
    report = analyze([str(folder)], reader="demo.xdt2:parse_file", limit=20, engine=engine)
    results = []
    for item in report["all_fields"]:
        data = (folder / item["file"]).read_bytes()
        pred = [tuple(x) for x in item["fields"]]
        results.append(evaluate_file(pred, xdt2.truth_fields(data), len(data)))
    return aggregate(results)


def test_v2_not_worse_than_v1_on_xdt2():
    v1, v2 = run("v1"), run("v2")
    assert v2["role_byte_accuracy"] >= v1["role_byte_accuracy"]
    assert v2["boundary_f1"] >= v1["boundary_f1"]


def test_v2_xdt2_regression_floor():
    s = run("v2")
    assert s["boundary_f1"] >= 0.97
    assert s["role_byte_accuracy"] >= 0.99
