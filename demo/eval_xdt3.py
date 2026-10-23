import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

CODE_PATHS = ["rebin.py", "recovery_audit.py", "experiments"]


def git(*args):
    try:
        return subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
    except Exception:
        return None


def main():
    out = ROOT / "results"
    target = out / "eval_xdt3_firstrun.json"
    if target.exists():
        raise SystemExit("Результат першого прогону вже існує; перезапис заборонено.")

    dirty = git("status", "--porcelain", "--", *CODE_PATHS)
    if dirty:
        raise SystemExit("Код алгоритму має незакомічені зміни. Закоміть їх і повтори:\n" + dirty)
    commit = git("rev-parse", "HEAD")

    from rebin import analyze
    from demo import xdt3
    from demo.eval_xdt import aggregate, evaluate_file, render

    samples = xdt3.generate()
    lines, data = [f"Версія коду: {commit}", ""], {"code_commit": commit}
    for engine in ("v1", "v2"):
        report = analyze([str(samples)], reader="demo.xdt3:parse_file", limit=20, engine=engine)
        results = []
        for item in report["all_fields"]:
            raw = (samples / item["file"]).read_bytes()
            pred = [tuple(x) for x in item["fields"]]
            results.append(evaluate_file(pred, xdt3.truth_fields(raw), len(raw)))
        summary = aggregate(results)
        data[engine] = summary
        lines += [f"=== алгоритм {engine} ===", render(summary), ""]

    text = "\n".join(lines)
    print(text)
    out.mkdir(exist_ok=True)
    (out / "eval_xdt3_firstrun.txt").write_text(text + "\n", encoding="utf-8")
    target.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print("Saved: results/eval_xdt3_firstrun.txt, results/eval_xdt3_firstrun.json")


if __name__ == "__main__":
    main()
