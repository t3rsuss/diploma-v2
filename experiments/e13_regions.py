import collections
import csv
import importlib.util
import pathlib
import pickle
import random
import statistics
import sys
from io import BytesIO

import lightgbm as lgb
import numpy as np
from kaitaistruct import KaitaiStream, KaitaiStruct

BASE = pathlib.Path(__file__).resolve().parents[1]
GEN = BASE / "kaitai_dbg"
CACHE = BASE / "results" / "e13_cache.pkl"
sys.path.append(str(GEN))
sys.setrecursionlimit(10000)
BS, BLOB, MAX_BYTES, PER_CLASS, MIN_COV, SEED, TOL = 256, 64, 300_000, 60, 0.98, 42, 1
FORMATS = {
    "png": ("png", "Png"), "gif": ("gif", "Gif"), "ico": ("ico", "Ico"), "wav": ("wav", "Wav"),
    "gz": ("gzip", "Gzip"), "docx": ("zip", "Zip"),
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


def block_feats(data):
    n = len(data)
    nb = (n + BS - 1) // BS
    pad = np.zeros(nb * BS, np.uint8)
    pad[:n] = np.frombuffer(data, np.uint8)
    valid = np.full(nb, BS, float)
    valid[-1] = n - (nb - 1) * BS
    idx = np.repeat(np.arange(nb), BS) * 256 + pad.astype(np.int64)
    cnt = np.bincount(idx, minlength=nb * 256).reshape(nb, 256).astype(float)
    cnt[-1, 0] -= BS - valid[-1]
    p = cnt / valid[:, None]
    ent = -(p * np.log2(np.where(p > 0, p, 1))).sum(1)
    asc = p[:, 32:127].sum(1) + p[:, [9, 10, 13]].sum(1)
    chi = ((cnt - valid[:, None] / 256) ** 2 / (valid[:, None] / 256)).sum(1) / valid
    diff = np.abs(np.diff(pad.reshape(nb, BS).astype(np.int16), axis=1)).mean(1)
    base = np.column_stack([ent, p[:, 0], asc, p[:, 128:].sum(1), chi, diff, p.reshape(nb, 16, 16).sum(2)])
    prev = np.vstack([base[:1], base[:-1]])
    nxt = np.vstack([base[1:], base[-1:]])
    pos = np.arange(nb)
    posf = np.column_stack([np.minimum(pos, 8), np.minimum(nb - 1 - pos, 8), pos / max(nb - 1, 1), np.full(nb, np.log2(nb + 1))])
    return np.hstack([base, prev[:, :6], nxt[:, :6], posf])


def build():
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
    data_all = {}
    for c, (mod, cls) in FORMATS.items():
        Parser = load(mod, cls)
        lst = sorted(files[c])
        rng.shuffle(lst)
        items, tried = [], 0
        for p in lst:
            if len(items) >= PER_CLASS:
                break
            try:
                if p.stat().st_size > MAX_BYTES or p.stat().st_size < 1024:
                    continue
                data = p.read_bytes()
            except OSError:
                continue
            tried += 1
            try:
                obj = Parser(KaitaiStream(BytesIO(data)))
                obj._read()
                rngs = []
                walk(obj, 0, rngs, {id(obj)})
                lab, cov = block_labels(rngs, len(data))
                if cov < MIN_COV:
                    continue
                items.append((p.name, block_feats(data), lab))
            except Exception:
                continue
        data_all[c] = items
        print(f"{c}: перевірено {tried}, прийнято {len(items)}", flush=True)
    return data_all


if CACHE.exists():
    data_all = pickle.load(open(CACHE, "rb"))
else:
    data_all = build()
    pickle.dump(data_all, open(CACHE, "wb"))


def smooth(lab):
    return np.array([int(round(np.mean(lab[max(0, i - 1):i + 2]))) for i in range(len(lab))])


def boundaries(lab):
    out, prev = [], None
    for i, v in enumerate(lab):
        if v < 0:
            continue
        if prev is not None and v != prev:
            out.append(i)
        prev = v
    return out


def match(tb, pb):
    used, tp = set(), 0
    for t in tb:
        cand = [(abs(p - t), j) for j, p in enumerate(pb) if j not in used]
        if cand:
            d, j = min(cand)
            if d <= TOL:
                used.add(j)
                tp += 1
    return tp


def stack(fmts):
    X = np.vstack([f[l >= 0] for c in fmts for _, f, l in data_all[c]])
    y = np.concatenate([l[l >= 0] for c in fmts for _, f, l in data_all[c]])
    return X, y


fmts = [c for c in FORMATS if data_all.get(c)]
print(f"\n{'тест-формат':12s}{'файлів':>7s}{'блоків':>8s}{'наповн.,%':>10s}{'ент.:точн.%':>12s}{'мод.:точн.%':>12s}"
      f"{'ент.:F1 меж':>13s}{'мод.:F1 меж':>13s}")
rows = []
for held in fmts:
    Xtr, ytr = stack([c for c in fmts if c != held])
    grid = np.arange(4.0, 7.95, 0.1)
    thr = max(grid, key=lambda t: np.mean((Xtr[:, 0] > t) == ytr))
    clf = lgb.LGBMClassifier(n_estimators=200, num_leaves=15, learning_rate=0.08, subsample=0.8,
                             subsample_freq=1, colsample_bytree=0.7, class_weight="balanced",
                             random_state=SEED, verbose=-1, n_jobs=-1)
    clf.fit(Xtr, ytr)
    nb = ok_e = ok_m = 0
    pay = 0
    st = {"e": [0, 0, 0], "m": [0, 0, 0]}
    for _, f, l in data_all[held]:
        v = l >= 0
        pe = (f[:, 0] > thr).astype(int)
        pm = clf.predict(f).astype(int)
        nb += v.sum()
        pay += (l[v] == 1).sum()
        ok_e += (pe[v] == l[v]).sum()
        ok_m += (pm[v] == l[v]).sum()
        tb = boundaries(l)
        for key, pr in (("e", pe), ("m", pm)):
            pb = boundaries(np.where(v, smooth(pr), -1))
            st[key][0] += match(tb, pb)
            st[key][1] += len(pb)
            st[key][2] += len(tb)

    def f1(key):
        tp, npred, nt = st[key]
        p = tp / npred if npred else 0.0
        r = tp / nt if nt else 0.0
        return 2 * p * r / (p + r) if p + r else 0.0

    rows.append((held, len(data_all[held]), nb, 100 * pay / nb, 100 * ok_e / nb, 100 * ok_m / nb, f1("e"), f1("m")))
    print(f"{held:12s}{len(data_all[held]):7d}{nb:8d}{100 * pay / nb:10.1f}{100 * ok_e / nb:12.1f}{100 * ok_m / nb:12.1f}"
          f"{f1('e'):13.2f}{f1('m'):13.2f}   (поріг ентропії {thr:.1f})")
print(f"\nМакро: ентропія {np.mean([r[4] for r in rows]):.1f} %, модель {np.mean([r[5] for r in rows]):.1f} %; "
      f"F1 меж: ентропія {np.mean([r[6] for r in rows]):.2f}, модель {np.mean([r[7] for r in rows]):.2f}")