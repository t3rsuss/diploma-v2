import collections
import csv
import importlib.util
import pathlib
import random
import statistics
import sys
from io import BytesIO

from kaitaistruct import KaitaiStream, KaitaiStruct

BASE = pathlib.Path(__file__).resolve().parents[1]
GEN = BASE / "kaitai_dbg"
sys.path.append(str(GEN))
sys.setrecursionlimit(10000)
PER_CLASS, MAX_BYTES, SEED, BLOB = 150, 3_000_000, 42, 256
FORMATS = {
    "png": ("png", "Png"), "gif": ("gif", "Gif"), "ico": ("ico", "Ico"), "wav": ("wav", "Wav"),
    "gz": ("gzip", "Gzip"), "sqlite": ("sqlite3", "Sqlite3"), "ttf": ("ttf", "Ttf"), "docx": ("zip", "Zip"),
}


def load(modname, clsname):
    spec = importlib.util.spec_from_file_location("kd_" + modname, GEN / (modname + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return getattr(mod, clsname)


def touch(obj):
    for pname, attr in type(obj).__dict__.items():
        if isinstance(attr, property) and not pname.startswith("_"):
            try:
                getattr(obj, pname)
            except Exception:
                pass


def visit(val, parent, base, s, e, out, seen):
    if isinstance(val, KaitaiStruct):
        if id(val) in seen:
            return
        seen.add(id(val))
        child_base = base if val._io is parent._io else base + s
        before = len(out)
        walk(val, child_base, out, seen)
        if len(out) == before:
            out.append((base + s, base + e, False))
    else:
        opaque = isinstance(val, (bytes, bytearray)) and (e - s) >= BLOB
        out.append((base + s, base + e, opaque))


def walk(obj, base, out, seen):
    touch(obj)
    dbg = getattr(obj, "_debug", None)
    if not dbg:
        return
    for name, info in list(dbg.items()):
        try:
            val = getattr(obj, name)
        except Exception:
            continue
        if "arr" in info and isinstance(val, list):
            for item, ai in zip(val, info["arr"]):
                visit(item, obj, base, ai["start"], ai["end"], out, seen)
        elif info.get("start") is not None and info.get("end") is not None:
            visit(val, obj, base, info["start"], info["end"], out, seen)


def covered(ranges, n):
    iv = sorted((max(0, s), min(n, e)) for s, e in ranges)
    iv = [(s, e) for s, e in iv if e > s]
    total, cs, ce = 0, None, None
    for s, e in iv:
        if ce is None or s > ce:
            if ce is not None:
                total += ce - cs
            cs, ce = s, e
        else:
            ce = max(ce, e)
    if ce is not None:
        total += ce - cs
    return total


files = collections.defaultdict(set)
with open(BASE / "results" / "corpus_manifest_frozen.csv", encoding="utf-8", newline="") as fh:
    for r in csv.DictReader(fh):
        c = r["format"]
        if c in FORMATS:
            ext = r["ext"]
            p = BASE / "data" / "corpus" / c / (r["sha256"][:12] + ("." + ext if ext else ""))
            if p.exists():
                files[c].add(p)
for name in ("govdocs_dev.csv", "govdocs_test.csv"):
    with open(BASE / "results" / name, encoding="utf-8", newline="") as fh:
        for r in csv.DictReader(fh):
            if r["format"] in ("gif", "gz") and r["format"] in FORMATS:
                files[r["format"]].add(pathlib.Path(r["src"]))

rng = random.Random(SEED)
stat = {}
for c, (mod, cls) in FORMATS.items():
    Parser = load(mod, cls)
    lst = sorted(files[c])
    rng.shuffle(lst)
    st = dict(n=0, ok=0, all=[], struct=[], ball=0, bstr=0, btot=0, errs=collections.Counter(), fields=[])
    for p in lst:
        if st["n"] >= PER_CLASS:
            break
        try:
            if p.stat().st_size > MAX_BYTES:
                continue
            data = p.read_bytes()
        except OSError:
            continue
        st["n"] += 1
        try:
            obj = Parser(KaitaiStream(BytesIO(data)))
            obj._read()
            rngs = []
            walk(obj, 0, rngs, {id(obj)})
            n = len(data)
            ca = covered([(s, e) for s, e, _ in rngs], n)
            cs = covered([(s, e) for s, e, o in rngs if not o], n)
            st["ok"] += 1
            st["all"].append(100 * ca / n)
            st["struct"].append(100 * cs / n)
            st["ball"] += ca
            st["bstr"] += cs
            st["btot"] += n
            st["fields"].append(len(rngs))
        except Exception as ex:
            st["errs"][type(ex).__name__] += 1
    stat[c] = st

print(f"{'формат':8s}{'файлів':>8s}{'розібрано,%':>13s}{'усі поля,%':>12s}{'структура,%':>13s}{'структ. за байт.,%':>20s}{'полів, мед.':>13s}")
for c, st in stat.items():
    if not st["n"]:
        print(f"{c:8s}{0:8d}")
        continue
    ok = 100 * st["ok"] / st["n"]
    ma = statistics.mean(st["all"]) if st["all"] else 0.0
    ms = statistics.mean(st["struct"]) if st["struct"] else 0.0
    bw = 100 * st["bstr"] / st["btot"] if st["btot"] else 0.0
    fm = statistics.median(st["fields"]) if st["fields"] else 0
    print(f"{c:8s}{st['n']:8d}{ok:13.1f}{ma:12.1f}{ms:13.1f}{bw:20.1f}{fm:13.0f}")
print(f"\n'структура' = поля, що не є масивами байтів від {BLOB} Б (непрозорі блоки не враховано)")
print("\nПричини невдач розбору")
for c, st in stat.items():
    if st["errs"]:
        print(f"  {c}: {dict(st['errs'].most_common(4))}")