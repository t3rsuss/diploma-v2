import collections
import csv
import gzip
import importlib.util
import io
import pathlib
import random
import sys
import wave
import zipfile
from io import BytesIO

import numpy as np
from kaitaistruct import KaitaiStream, KaitaiStruct
from PIL import Image

BASE = pathlib.Path(__file__).resolve().parents[1]
GEN = BASE / "kaitai_dbg"
sys.path.append(str(GEN))
sys.setrecursionlimit(10000)
BS, BLOB, MAX_BYTES, PER_CLASS, MIN_COV, SEED = 256, 64, 300_000, 40, 0.98, 42
FORMATS = {
    "png": ("png", "Png"), "gif": ("gif", "Gif"), "ico": ("ico", "Ico"), "wav": ("wav", "Wav"),
    "gz": ("gzip", "Gzip"), "docx": ("zip", "Zip"),
}


class TraceIO(io.BytesIO):
    def __init__(self, data):
        super().__init__(data)
        self.log = []

    def read(self, size=-1):
        pos = self.tell()
        out = super().read(size)
        self.log.append((pos, len(out)))
        return out

    def read1(self, size=-1):
        return self.read(size)

    def readline(self, size=-1):
        pos = self.tell()
        out = super().readline(size)
        self.log.append((pos, len(out)))
        return out

    def readinto(self, b):
        pos = self.tell()
        n = super().readinto(b) or 0
        self.log.append((pos, n))
        return n


def run_reader(fmt, data):
    f = TraceIO(data)
    if fmt in ("png", "gif", "ico"):
        im = Image.open(f)
        im.load()
    elif fmt == "wav":
        w = wave.open(f, "rb")
        w.readframes(w.getnframes())
    elif fmt == "gz":
        with gzip.GzipFile(fileobj=f) as g:
            while g.read(1 << 16):
                pass
    elif fmt == "docx":
        with zipfile.ZipFile(f) as z:
            for n in z.namelist():
                z.read(n)
    return [(p, l) for p, l in f.log if l > 0]


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
        out.append((base + s, base + e, (e - s) >= BLOB and isinstance(val, (bytes, bytearray, list))))


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
        s, e = info.get("start"), info.get("end")
        if "arr" in info and isinstance(val, list):
            if val and s is not None and e is not None and not any(isinstance(x, KaitaiStruct) for x in val):
                out.append((base + s, base + e, (e - s) >= BLOB))
                continue
            for item, ai in zip(val, info["arr"]):
                visit(item, obj, base, ai["start"], ai["end"], out, seen)
        elif s is not None and e is not None:
            visit(val, obj, base, s, e, out, seen)


def block_labels(ranges, n):
    nb = (n + BS - 1) // BS
    pb, sb = np.zeros(n, bool), np.zeros(n, bool)
    for s, e, o in ranges:
        s, e = max(0, s), min(n, e)
        if e > s:
            (pb if o else sb)[s:e] = True
    sb &= ~pb
    cov = pb | sb
    lab = np.full(nb, -1)
    for i in range(nb):
        a, b = i * BS, min(n, (i + 1) * BS)
        if cov[a:b].sum() >= 0.5 * (b - a):
            lab[i] = 1 if pb[a:b].sum() >= sb[a:b].sum() else 0
    return lab, float(cov.mean())


def trace_block_labels(log, n):
    nb = (n + BS - 1) // BS
    small = np.zeros(n, bool)
    for p, l in log:
        if l < BLOB:
            small[p:min(n, p + l)] = True
    lab = np.ones(nb, int)
    for i in range(nb):
        a, b = i * BS, min(n, (i + 1) * BS)
        if small[a:b].sum() >= 0.5 * (b - a):
            lab[i] = 0
    return lab


def edges(intervals, n):
    s = set()
    for a, b in intervals:
        s.add(a)
        s.add(b)
    s.discard(0)
    s.discard(n)
    return s


def near(a, b, tol):
    if not b:
        return 0
    bs = np.array(sorted(b))
    c = 0
    for x in a:
        i = int(np.searchsorted(bs, x))
        d = min(abs(bs[i] - x) if i < len(bs) else 1 << 60, abs(bs[i - 1] - x) if i > 0 else 1 << 60)
        c += d <= tol
    return c


def boundaries(lab):
    out, prev = [], None
    for i, v in enumerate(lab):
        if v < 0:
            continue
        if prev is not None and v != prev:
            out.append(i)
        prev = v
    return out


def match(tb, pb, tol):
    used, tp = set(), 0
    for t in tb:
        cand = [(abs(p - t), j) for j, p in enumerate(pb) if j not in used]
        if cand:
            d, j = min(cand)
            if d <= tol:
                used.add(j)
                tp += 1
    return tp


def f1(tp, npred, nt):
    p = tp / npred if npred else 0.0
    r = tp / nt if nt else 0.0
    return 2 * p * r / (p + r) if p + r else 0.0


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
            if r["format"] in ("gif", "gz"):
                files[r["format"]].add(pathlib.Path(r["src"]))

rng = random.Random(SEED)
print(f"{'формат':7s}{'файлів':>7s}{'прочит.,%':>10s}{'меж: P0':>9s}{'R0':>6s}{'P2':>6s}{'R2':>6s}"
      f"{'F1 структ.':>12s}{'F1 меж±1':>10s}{'F1 меж±4':>10s}")
macro = collections.defaultdict(list)
for c, (mod, cls) in FORMATS.items():
    Parser = load(mod, cls)
    lst = sorted(files[c])
    rng.shuffle(lst)
    n_ok = 0
    read_frac = []
    cnt = {t: [0, 0, 0, 0] for t in (0, 2)}
    sf = [0, 0, 0]
    bf = {1: [0, 0, 0], 4: [0, 0, 0]}
    for p in lst:
        if n_ok >= PER_CLASS:
            break
        try:
            if not (1024 <= p.stat().st_size <= MAX_BYTES):
                continue
            data = p.read_bytes()
            obj = Parser(KaitaiStream(BytesIO(data)))
            obj._read()
            rngs = []
            walk(obj, 0, rngs, {id(obj)})
            tl, cov = block_labels(rngs, len(data))
            if cov < MIN_COV:
                continue
            log = run_reader(c, data)
        except Exception:
            continue
        n = len(data)
        n_ok += 1
        mask = np.zeros(n, bool)
        for pos, ln in log:
            mask[pos:min(n, pos + ln)] = True
        read_frac.append(100 * mask.mean())
        T = edges([(s, e) for s, e, _ in rngs], n)
        P = edges([(pos, pos + ln) for pos, ln in log], n)
        for t in cnt:
            cnt[t][0] += near(T, P, t)
            cnt[t][1] += len(T)
            cnt[t][2] += near(P, T, t)
            cnt[t][3] += len(P)
        pl = trace_block_labels(log, n)
        v = tl >= 0
        sf[0] += ((tl == 0) & (pl == 0) & v).sum()
        sf[1] += ((pl == 0) & v).sum()
        sf[2] += ((tl == 0) & v).sum()
        tb = boundaries(tl)
        pb = boundaries(np.where(v, pl, -1))
        for t in bf:
            bf[t][0] += match(tb, pb, t)
            bf[t][1] += len(pb)
            bf[t][2] += len(tb)
    if not n_ok:
        print(f"{c:7s}{0:7d}")
        continue

    def pr(t):
        r_ = cnt[t][0] / cnt[t][1] if cnt[t][1] else 0.0
        p_ = cnt[t][2] / cnt[t][3] if cnt[t][3] else 0.0
        return p_, r_

    p0, r0 = pr(0)
    p2, r2 = pr(2)
    fs = f1(sf[0], sf[1], sf[2])
    b1, b4 = f1(*bf[1]), f1(*bf[4])
    macro["fs"].append(fs)
    macro["b1"].append(b1)
    macro["b4"].append(b4)
    print(f"{c:7s}{n_ok:7d}{np.mean(read_frac):10.1f}{p0:9.2f}{r0:6.2f}{p2:6.2f}{r2:6.2f}{fs:12.2f}{b1:10.2f}{b4:10.2f}",
          flush=True)
print(f"\nМакро: F1 структури {np.mean(macro['fs']):.2f}, F1 меж ±1 блок {np.mean(macro['b1']):.2f}, "
      f"±4 блоки {np.mean(macro['b4']):.2f}")
print("Порівняння зі статистикою вмісту (e14): F1 структури 0,21; F1 меж ±1 блок 0,24; ±4 блоки 0,25")