import json
import pathlib
import random
import subprocess
import sys
from io import BytesIO

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments"))

FORMATS = ["png", "gif", "ico", "wav", "gz", "docx"]
PER_CLASS, SEED = 30, 42


def git(*args):
    try:
        return subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
    except Exception:
        return None


def main():
    import trace_lib as T
    import e17_inference as INF
    import e18_context as CTX
    import e20_infer2 as INF2
    from kaitaistruct import KaitaiStream

    files = T.collect_files()
    rng = random.Random(SEED)
    table = []
    lines = [
        f"Версія коду: {git('rev-parse', 'HEAD')}",
        f"{'формат':7s}{'файлів':>7s}{'алг.':>6s}{'точність':>10s}{'повнота':>9s}{'F1':>7s}{'полів/файл':>12s}",
    ]

    for c in FORMATS:
        mod, cls = T.FORMATS[c]
        Parser = T.load(mod, cls)
        lst = sorted(files[c])
        rng.shuffle(lst)
        items = []
        for p in lst:
            if len(items) >= PER_CLASS:
                break
            try:
                if not (1024 <= p.stat().st_size <= 150_000):
                    continue
                data = p.read_bytes()
                log = CTX.run_ctx(c, data)
                if not log or len(log) > 3000:
                    continue
                obj = Parser(KaitaiStream(BytesIO(data)))
                obj._read()
                rngs = []
                T.walk(obj, 0, rngs, {id(obj)})
            except Exception:
                continue
            size = len(data)
            truth = {x for s, e, _ in rngs for x in (s, e)} - {0, size}
            items.append((data, log, truth))

        if len(items) < 5:
            lines.append(f"{c:7s}замало файлів ({len(items)})")
            continue

        for engine in ("v1", "v2"):
            if engine == "v1":
                inferred = INF.infer([(d, [(p_, l) for p_, l, _ in lg]) for d, lg, _ in items])
            else:
                inferred = INF2.infer2([(d, lg) for d, lg, _ in items])
            tp = npred = ntrue = nfields = 0
            for (d, lg, truth), f in zip(items, inferred):
                size = len(d)
                pe = {x for a, b, _ in f for x in (a, b)} - {0, size}
                tp += len(pe & truth)
                npred += len(pe)
                ntrue += len(truth)
                nfields += len(f)
            prec = tp / npred if npred else 0.0
            rec = tp / ntrue if ntrue else 0.0
            f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
            table.append({
                "format": c, "files": len(items), "engine": engine,
                "precision": prec, "recall": rec, "f1": f1,
                "fields_per_file": nfields / len(items),
            })
            lines.append(
                f"{c:7s}{len(items):7d}{engine:>6s}{100 * prec:9.1f}%{100 * rec:8.1f}%"
                f"{f1:7.3f}{nfields / len(items):12.1f}"
            )

    text = "\n".join(lines)
    print(text)
    out = ROOT / "results"
    out.mkdir(exist_ok=True)
    (out / "eval_real_kaitai.txt").write_text(text + "\n", encoding="utf-8")
    (out / "eval_real_kaitai.json").write_text(
        json.dumps(table, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print("Saved: results/eval_real_kaitai.txt, results/eval_real_kaitai.json")


if __name__ == "__main__":
    main()
