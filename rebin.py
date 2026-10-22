from recovery_audit import audit_intervals
r"""rebin: відновлення структури невідомого бінарного формату за трасуванням програми-читача.

Приклади:
  python rebin.py data/corpus/png --format png
  python rebin.py samples/ --reader mymod:parse_file --out results/my_format.json
Читач: функція f(fp), яка розбирає відкритий файловий об'єкт (читає через fp.read / fp.seek).
"""
import argparse
import collections
import importlib
import json
import pathlib
import random
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "experiments"))
sys.path.insert(0, str(pathlib.Path.cwd()))

import e17_inference as INF
import e18_context as CTX

CTX.GENERIC.add("_trace_custom")


def _trace_custom(func, data):
    f = CTX.CtxIO(data)
    func(f)
    return f.log


def load_reader(spec):
    mod, _, name = spec.partition(":")
    return getattr(importlib.import_module(mod), name)


def collect(paths, limit, min_size, max_size, seed=42):
    files = []
    for p in map(pathlib.Path, paths):
        files += [x for x in p.rglob("*") if x.is_file()] if p.is_dir() else [p]
    files = sorted(set(files))
    random.Random(seed).shuffle(files)
    return [f for f in files if min_size <= f.stat().st_size <= max_size][:limit]


def label_for(a, b, log):
    best = None
    for pos, ln, ctx in log:
        if pos <= a and b <= pos + ln and ctx != "?":
            if best is None or ln < best[0]:
                best = (ln, ctx)
    if best:
        return best[1]
    for pos, ln, ctx in log:
        if pos < b and a < pos + ln:
            return ctx
    return "(не читалось)"


def analyze(paths, fmt=None, reader=None, limit=30, min_size=64, max_size=300_000):
    func = load_reader(reader) if reader else None
    if not (fmt or func):
        raise SystemExit("потрібно вказати --format або --reader")
    samples, logs, names = [], [], []
    for p in collect(paths, limit * 3, min_size, max_size):
        if len(samples) >= limit:
            break
        data = p.read_bytes()
        try:
            log = CTX.run_ctx(fmt, data) if func is None else _trace_custom(func, data)
        except Exception:
            continue
        if not log:
            continue
        samples.append((data, [(pos, ln) for pos, ln, _ in log]))
        logs.append(log)
        names.append(p.name)
    if len(samples) < 5:
        raise SystemExit(f"замало придатних файлів: {len(samples)} (потрібно хоча б 5)")
    inferred = INF.infer(samples)

    audits = []
    for name, (data, log), fields in zip(names, samples, inferred):
        audit = audit_intervals(
            [(start, end) for start, end, role in fields],
            len(data),
        )
        audits.append({"file": name, **audit})
    roles = collections.Counter()
    for fields in inferred:
        for a, b, r in fields:
            roles[r] += b - a
    tot = sum(roles.values()) or 1
    first = [
        {"start": a, "end": b, "size": b - a, "role": r, "context": label_for(a, b, logs[0]),
         "hex": samples[0][0][a:min(b, a + 8)].hex()}
        for a, b, r in inferred[0]
    ]
    return {
        "files": len(samples),
        "example_file": names[0],
        "interval_audit": audits[0],
        "interval_audits": audits,
        "points": [
            {"context": r[0], "files_share": round(r[1], 3), "per_file": round(r[2], 2), "length": r[3],
             "length_share": round(r[4], 3), "role": r[6]}
            for r in CTX.profile(logs)
        ],
        "role_byte_share": {k: round(v / tot, 4) for k, v in roles.most_common()},
        "example_fields": first,
    }


def show(rep, limit=24):
    print(f"Файлів проаналізовано: {rep['files']}; приклад: {rep['example_file']}")
    print("Частка байтів за ролями:", {k: f"{100 * v:.1f} %" for k, v in rep["role_byte_share"].items()})
    stable = sum(1 for p in rep["points"] if p["files_share"] >= 0.9)
    print(f"Точок читання: {len(rep['points'])}, стабільних (>=90 % файлів): {stable}")
    print("Відновлений опис першого файла:")
    print(f"  {'зсув':>14s} {'розмір':>8s}  {'роль':14s} {'точка читання':40s} hex")
    for f in rep["example_fields"][:limit]:
        print(f"  {f['start']:6d}..{f['end']:<6d} {f['size']:8d}  {f['role']:14s} {f['context'][:40]:40s} {f['hex']}")
    if len(rep["example_fields"]) > limit:
        print(f"  ... ще {len(rep['example_fields']) - limit} полів (див. JSON)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="файли або каталоги зі зразками одного формату")
    ap.add_argument("--format", choices=["png", "gif", "ico", "wav", "gz", "docx"], help="вбудований читач")
    ap.add_argument("--reader", help="власний читач: модуль:функція (приймає файловий об'єкт)")
    ap.add_argument("--limit", type=int, default=30)
    ap.add_argument("--out", help="шлях JSON-звіту")
    a = ap.parse_args()
    rep = analyze(a.paths, a.format, a.reader, a.limit)
    show(rep)
    if a.out:
        pathlib.Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(a.out).write_text(json.dumps(rep, ensure_ascii=False, indent=1), encoding="utf-8")
        print("Звіт записано:", a.out)


if __name__ == "__main__":
    main()
