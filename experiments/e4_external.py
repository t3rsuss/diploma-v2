import collections
import csv
import hashlib
import json
import pathlib
import random
import xml.etree.ElementTree as ET
import zlib

import lightgbm as lgb
import numpy as np
from magika import Magika

BASE = pathlib.Path(r"C:\Users\vlad\Desktop\diploma-v2")
MANIFEST = BASE / "results" / "corpus_manifest_frozen.csv"
CORPUS = BASE / "data" / "corpus"
EXT = BASE / "data" / "ext_corpus"
REPORT = BASE / "results" / "e4_external_report_v2.txt"
WIN, TRAIN_WIN, TEST_WIN, PER, MIN_FILES, SEED = 4096, 40, 5, 40, 20, 42
rng = random.Random(SEED)
DIRMAP = {"conf": "ini", "cfg": "ini"}
MG = {
    "png": {"png"}, "jpg": {"jpeg"}, "gif": {"gif"}, "ico": {"ico"}, "pdf": {"pdf"},
    "gz": {"gzip"}, "sqlite": {"sqlite"}, "wav": {"wav"}, "json": {"json"},
    "xml": {"xml"}, "html": {"html"}, "txt": {"txt"}, "ttf": {"ttf"},
    "ini": {"ini", "internetshortcut"}, "csv": {"csv", "tsv"},
    "log": {"txt", "log", "syslog"},
}
SIG = {
    "png": lambda b: b[:8] == b"\x89PNG\r\n\x1a\n",
    "jpg": lambda b: b[:3] == b"\xff\xd8\xff",
    "gif": lambda b: b[:6] in (b"GIF87a", b"GIF89a"),
    "ico": lambda b: b[:4] == b"\x00\x00\x01\x00",
    "pdf": lambda b: b[:5] == b"%PDF-",
    "gz": lambda b: b[:3] == b"\x1f\x8b\x08",
    "sqlite": lambda b: b[:16] == b"SQLite format 3\x00",
    "wav": lambda b: b[:4] == b"RIFF" and b[8:12] == b"WAVE",
    "ttf": lambda b: b[:4] in (b"\x00\x01\x00\x00", b"true"),
}
lines = []


def out(s=""):
    print(s)
    lines.append(str(s))


def feats(b):
    a = np.frombuffer(b, dtype=np.uint8)
    n = len(a)
    hist = np.bincount(a, minlength=256).astype(np.float32)
    p = hist / n
    nz = p[p > 0]
    ent = float(-(nz * np.log2(nz)).sum())
    chi = float(((hist - n / 256) ** 2 / (n / 256)).sum() / n)
    zr = len(zlib.compress(b, 1)) / n
    ent2, dif, ac, run = 0.0, 0.0, 0.0, 1.0
    if n > 1:
        pair = a[:-1].astype(np.int32) * 256 + a[1:]
        c2 = np.bincount(pair, minlength=65536)
        q = c2[c2 > 0] / (n - 1)
        ent2 = float(-(q * np.log2(q)).sum()) / 16
        dif = float(np.abs(np.diff(a.astype(np.int16))).mean()) / 255
        if a.std() > 0:
            ac = float(np.corrcoef(a[:-1], a[1:])[0, 1])
        cut = np.flatnonzero(a[1:] != a[:-1])
        run = float(np.diff(np.concatenate(([0], cut + 1, [n]))).max()) / n
    ll = np.array([len(x) for x in b.split(b"\n")], dtype=np.float32)
    extra = [ent, p[0], p[255], p[32:127].sum(), p[128:].sum(), a.mean() / 255,
             a.std() / 255, (hist > 0).sum() / 256, zr, chi, ent2, dif, ac, run,
             len(ll) / 100.0, ll.mean() / 100.0, ll.std() / 100.0]
    return np.concatenate([p, np.array(extra, dtype=np.float32)])


def windows(data, k, r):
    n = len(data)
    if n <= WIN:
        return [data]
    return [data[o:o + WIN] for o in (r.randrange(0, n - WIN + 1) for _ in range(k))]


def valid(cls, b):
    if cls in SIG:
        return SIG[cls](b)
    try:
        t = b[:2_000_000].decode("utf-8")
    except UnicodeDecodeError:
        return False
    s = t.lstrip()
    if len(s) < 100 or "\x00" in t:
        return False
    try:
        if cls == "json":
            return s[0] in "{[" and isinstance(json.loads(t), (dict, list))
        if cls == "xml":
            ET.fromstring(t)
            return s.startswith("<")
        if cls == "html":
            return "<html" in s[:2000].lower() or "<!doctype html" in s[:2000].lower()
    except Exception:
        return False
    return s[0] not in "<{["


with open(MANIFEST, encoding="utf-8", newline="") as fh:
    rows = list(csv.DictReader(fh))
by = collections.defaultdict(list)
for r in rows:
    by[r["format"]].append(r)
classes = sorted(c for c, v in by.items() if len(v) >= MIN_FILES)
Xtr, ytr = [], []
for ci, c in enumerate(classes):
    for it in by[c]:
        ext = it["ext"]
        data = (CORPUS / c / (it["sha256"][:12] + ("." + ext if ext else ""))).read_bytes()
        r = random.Random(int(it["sha256"][:8], 16) + 1)
        for w in windows(data, TRAIN_WIN, r):
            Xtr.append(feats(w))
            ytr.append(ci)
out(f"Навчання: {len(classes)} класів, {len(ytr)} вікон, ознак {len(Xtr[0])}")
clf = lgb.LGBMClassifier(n_estimators=300, learning_rate=0.08, num_leaves=31,
                         subsample=0.8, subsample_freq=1, colsample_bytree=0.5,
                         class_weight="balanced", random_state=SEED, verbose=-1, n_jobs=-1)
clf.fit(np.array(Xtr), np.array(ytr))

ext_files = collections.defaultdict(list)
seen, rejected = set(), collections.Counter()
for d in sorted(EXT.iterdir()):
    cls = DIRMAP.get(d.name, d.name)
    if cls not in classes:
        continue
    for p in sorted(d.iterdir()):
        b = p.read_bytes()
        h = hashlib.sha256(b).hexdigest()
        if len(b) < 512 or h in seen:
            continue
        if not valid(cls, b):
            rejected[cls] += 1
            continue
        seen.add(h)
        ext_files[cls].append(b)
out("Відхилено перевіркою вмісту: " + str(dict(rejected)))

tests = []
for c, lst in ext_files.items():
    rng.shuffle(lst)
    for b in lst[:PER]:
        for w in windows(b, TEST_WIN, rng):
            tests.append((c, w))
yte = np.array([classes.index(c) for c, _ in tests])
Xte = np.array([feats(w) for _, w in tests])
pred = clf.predict(Xte)
conf = clf.predict_proba(Xte).max(axis=1)
mg = Magika()
lab = []
for _, w in tests:
    r = mg.identify_bytes(w)
    lab.append(str(r.output.label) if r.ok else "error")

out(f"Тестових вікон: {len(tests)}")
out()
out(f"{'клас':8s}{'файлів':>8s}{'вікон':>7s}{'власна':>8s}{'Magika':>8s}{'unknown':>9s}")
own_m, mg_m = [], []
for c in sorted(ext_files):
    ci = classes.index(c)
    idx = np.where(yte == ci)[0]
    own = float((pred[idx] == ci).mean())
    okm = float(np.mean([lab[i] in MG[c] for i in idx]))
    unk = float(np.mean([lab[i] == "unknown" for i in idx]))
    own_m.append(own)
    mg_m.append(okm)
    out(f"{c:8s}{min(len(ext_files[c]), PER):8d}{len(idx):7d}{100 * own:8.1f}{100 * okm:8.1f}{100 * unk:9.1f}")
out()
out(f"Макро, власна модель: {100 * np.mean(own_m):.1f} %, Magika: {100 * np.mean(mg_m):.1f} %")
out()
out("Охоплення і точність серед відповідей, макро, %")
for t in (0.0, 0.7, 0.9):
    cov, acc = [], []
    for c in sorted(ext_files):
        idx = np.where(yte == classes.index(c))[0]
        m = conf[idx] >= t
        cov.append(m.mean())
        acc.append((pred[idx][m] == classes.index(c)).mean() if m.any() else 0.0)
    out(f"  власна {t}: охоплення {100 * np.mean(cov):.1f}, точність {100 * np.mean(acc):.1f}")
cov, acc = [], []
for c in sorted(ext_files):
    idx = np.where(yte == classes.index(c))[0]
    ans = [i for i in idx if lab[i] != "unknown"]
    cov.append(len(ans) / len(idx))
    acc.append(np.mean([lab[i] in MG[c] for i in ans]) if ans else 0.0)
out(f"  Magika: охоплення {100 * np.mean(cov):.1f}, точність {100 * np.mean(acc):.1f}")
out()
out("Помилки власної моделі (клас -> що передбачено)")
for c in sorted(ext_files):
    ci = classes.index(c)
    idx = np.where(yte == ci)[0]
    wrong = collections.Counter(classes[p] for p in pred[idx] if p != ci)
    if wrong and (pred[idx] == ci).mean() < 0.9:
        out(f"  {c:7s} {wrong.most_common(3)}")
REPORT.write_text("\n".join(lines), encoding="utf-8")
out(f"\nЗвіт: {REPORT}")