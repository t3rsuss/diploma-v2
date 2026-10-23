import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def git(*args):
    try:
        return subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
    except Exception:
        return None


def main():
    dirty = git("status", "--porcelain", "--", "rebin.py", "recovery_audit.py", "experiments")
    if dirty:
        raise SystemExit("Код алгоритму не закомічено. Закоміть і повтори:\n" + dirty)
    commit = git("rev-parse", "HEAD")

    from rebin import analyze
    from demo import xdt3
    from demo.eval_xdt import aggregate, evaluate_file, render

    samples = xdt3.generate()
    report = analyze([str(samples)], reader="demo.xdt3:parse_file", limit=20, engine="v2")
    results = []
    for item in report["all_fields"]:
        raw = (samples / item["file"]).read_bytes()
        pred = [tuple(x) for x in item["fields"]]
        results.append(evaluate_file(pred, xdt3.truth_fields(raw), len(raw)))

    s = aggregate(results)
    total = sum(r["total"] for r in s["by_role"].values())
    exact = sum(r.get("exact_correct", 0) for r in s["by_role"].values())
    text = "\n".join([
        f"Версія коду: {commit}",
        "Після виправлень v2c (post-hoc, не незалежний тест)",
        render(s),
        "",
        f"Точно визначених полів: {exact} з {total} ({100 * exact / total:.1f} %)",
    ])
    print(text)

    out = ROOT / "results"
    (out / "eval_xdt3_after_v2c.txt").write_text(text + "\n", encoding="utf-8")
    (out / "eval_xdt3_after_v2c.json").write_text(
        json.dumps({"code_commit": commit, "v2": s}, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print("Saved: results/eval_xdt3_after_v2c.txt, results/eval_xdt3_after_v2c.json")


if __name__ == "__main__":
    main()
