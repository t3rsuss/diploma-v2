import collections
import csv
import os
import pathlib
import random
import sys
import zlib

import lightgbm as lgb
import numpy as np
from magika import Magika
from sklearn.metrics import f1_score

SEED = int(sys.argv[1]) if len(sys.argv) > 1 else 42
BASE = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = BASE / "results" / "corpus_manifest_frozen.csv"
CORPUS = BASE / "data" / "corpus"
OUT = BASE / "results" / f"e3_fragments_s{SEED}.csv"
SPLIT = BASE / "results" / f"e3_split_s{SEED}.csv"
REPORT = BASE / "results" / f"e3_report_s{SEED}.txt"

WIN = 4096
TRAIN_WIN = 40
TEST_WIN = 5
TEST_FRAC = 0.3
MIN_FILES = 20
MIN_FOLDERS = 4
CHUNK = 8
rng = random.Random(SEED)

MG = {
    "png": {"png"}, "jpg": {"jpeg"}, "gif": {"gif"}, "bmp": {"bmp"}, "ico": {"ico"},
    "pdf": {"pdf"}, "zip": {"zip"}, "gz": {"gzip"}, "sqlite": {"sqlite"},
    "wav": {"wav"}, "mp3": {"mp3"}, "json": {"json"}, "xml": {"xml"},
    "html": {"html"}, "txt": {"txt"}, "ttf": {"ttf"}, "pe": {"pebin"},
    "elf": {"elf"}, "docx": {"docx"}, "xlsx": {"xlsx"}, "pptx": {"pptx"},
    "rtf": {"rtf"}, "lnk": {"lnk"}, "ole2": {"msi", "doc", "xls", "ppt", "ole"},
    "ini": {"ini", "internetshortcut"}, "csv": {"csv", "tsv"},
    "pcap": {"pcap", "pcapng"}, "log": {"txt", "log", "syslog"},
}

lines = []


def out(s=""):
    print(s)
    lines.append(str(s))


def path_of(it):
    ext = it["ext"]
    return CORPUS / it["format"] / (it["sha256"][:12] + ("." + ext if ext else ""))


def feats(b):
    a = np.frombuffer(b, dtype=np.uint8)
    n = len(a)
    hist = np.bincount(a, minlength=256).astype(np.float32)
    p = hist / n
    nz = p[p > 0]
    ent = float(-(nz * np.log2(nz)).sum())
    chi = float(((hist - n / 256) ** 2 / (n / 256)).sum() / n)
    zr = len(zlib.compress(b, 1)) / n
    extra = [ent, p[0], p[255], p[32:127].sum(), p[128:].sum(), a.mean() / 255,
             a.std() / 255, (hist > 0).sum() / 256, zr, chi]
    return np.concatenate([p, np.array(extra, dtype=np.float32)])


def windows(data, k, r):
    n = len(data)
    if n <= WIN:
        return [data]
    return [data[o:o + WIN] for o in (r.randrange(0, n - WIN + 1) for _ in range(k))]


def split(items):
    groups = collections.defaultdict(list)
    for it in sorted(items, key=lambda x: x["sha256"]):
        groups[os.path.dirname(it["src"])].append(it)
    parts = {}
    for k, v in groups.items():
        for i in range(0, len(v), CHUNK):
            parts[f"{k}#{i // CHUNK}"] = v[i:i + CHUNK]
    keys = sorted(parts)
    target = max(1, round(len(items) * TEST_FRAC))
    if len(keys) >= MIN_FOLDERS:
        rng.shuffle(keys)
        test = []
        for k in keys:
            if len(test) >= target:
                break
            if len(test) + len(parts[k]) > len(items) - 1:
                continue
            test += parts[k]
        if test and len(test) < len(items):
            ids = {id(x) for x in test}
            return [x for x in items if id(x) not in ids], test, "папки"
    sh = items[:]
    rng.shuffle(sh)
    return sh[target:], sh[:target], "файли"


with open(MANIFEST, encoding="utf-8", newline="") as fh:
    allrows = list(csv.DictReader(fh))
by_cls = collections.defaultdict(list)
for r in allrows:
    by_cls[r["format"]].append(r)
classes = sorted(c for c, v in by_cls.items() if len(v) >= MIN_FILES)
out(f"SEED = {SEED}")
out("Класи в експерименті: " + ", ".join(classes))

train, test, mode = {}, {}, {}
for c in classes:
    train[c], test[c], mode[c] = split(by_cls[c])

with open(SPLIT, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["cls", "sha12", "set", "mode"])
    for c in classes:
        for it in train[c]:
            w.writerow([c, it["sha256"][:12], "train", mode[c]])
        for it in test[c]:
            w.writerow([c, it["sha256"][:12], "test", mode[c]])

Xtr, ytr = [], []
for ci, c in enumerate(classes):
    for it in train[c]:
        data = path_of(it).read_bytes()
        r = random.Random(int(it["sha256"][:8], 16) + 1)
        for wnd in windows(data, TRAIN_WIN, r):
            Xtr.append(feats(wnd))
            ytr.append(ci)
Xtr = np.array(Xtr)
ytr = np.array(ytr)
out(f"Навчальних вікон: {len(ytr)}, ознак: {Xtr.shape[1]}")

clf = lgb.LGBMClassifier(n_estimators=300, learning_rate=0.08, num_leaves=31,
                         subsample=0.8, subsample_freq=1, colsample_bytree=0.5,
                         class_weight="balanced", random_state=SEED,
                         verbose=-1, n_jobs=-1)
clf.fit(Xtr, ytr)

tests = []
for ci, c in enumerate(classes):
    for it in test[c]:
        data = path_of(it).read_bytes()
        r = random.Random(int(it["sha256"][:8], 16) + 2)
        for wnd in windows(data, TEST_WIN, r):
            tests.append((ci, wnd))
yte = np.array([t[0] for t in tests])
Xte = np.array([feats(t[1]) for t in tests])
pred = clf.predict(Xte)
conf = clf.predict_proba(Xte).max(axis=1)
out(f"Тестових вікон: {len(tests)}")

mg = Magika()
mg_label = []
for _, wnd in tests:
    try:
        r = mg.identify_bytes(wnd)
        mg_label.append(str(r.output.label) if r.ok else "error")
    except Exception:
        mg_label.append("error")

out()
out("Охоплення і точність серед відповідей, макро за класами, %")
out(f"{'підхід':>12s}{'охоплення':>12s}{'точність':>10s}")
for t in (0.0, 0.5, 0.7, 0.9):
    cov, acc = [], []
    for ci in range(len(classes)):
        idx = np.where(yte == ci)[0]
        m = conf[idx] >= t
        cov.append(m.mean())
        acc.append((pred[idx][m] == ci).mean() if m.any() else 0.0)
    out(f"{'власна ' + str(t):>12s}{100 * np.mean(cov):12.1f}{100 * np.mean(acc):10.1f}")
cov, acc = [], []
for ci, c in enumerate(classes):
    if c not in MG:
        continue
    idx = np.where(yte == ci)[0]
    ans = [i for i in idx if mg_label[i] != "unknown"]
    cov.append(len(ans) / len(idx))
    acc.append(np.mean([mg_label[i] in MG[c] for i in ans]) if ans else 0.0)
out(f"{'Magika':>12s}{100 * np.mean(cov):12.1f}{100 * np.mean(acc):10.1f}")

rows = []
out()
out(f"{'клас':8s}{'розб.':>7s}{'train':>6s}{'test':>5s}{'вікон':>6s}{'власна':>8s}{'Magika':>8s}{'unknown':>9s}")
own_all, own_sup, mg_sup = [], [], []
for ci, c in enumerate(classes):
    idx = np.where(yte == ci)[0]
    own = float((pred[idx] == ci).mean())
    own_all.append(own)
    if c in MG:
        okm = float(np.mean([mg_label[i] in MG[c] for i in idx]))
        unk = float(np.mean([mg_label[i] == "unknown" for i in idx]))
        own_sup.append(own)
        mg_sup.append(okm)
        mtxt, utxt = f"{100 * okm:7.1f}", f"{100 * unk:8.1f}"
    else:
        okm, unk = float("nan"), float("nan")
        mtxt, utxt = f"{'нп':>7s}", f"{'-':>8s}"
    out(f"{c:8s}{mode[c]:>7s}{len(train[c]):>6d}{len(test[c]):>5d}{len(idx):>6d}"
        f"{100 * own:8.1f} {mtxt} {utxt}")
    rows.append([c, mode[c], len(train[c]), len(test[c]), len(idx),
                 round(own, 3), round(okm, 3), round(unk, 3)])

out()
out(f"Макро, власна модель, усі класи ({len(classes)}): {100 * np.mean(own_all):.1f} %")
out(f"Макро, власна модель, класи, які підтримує Magika ({len(own_sup)}): {100 * np.mean(own_sup):.1f} %")
out(f"Макро, Magika, ті самі класи: {100 * np.mean(mg_sup):.1f} %")
out(f"Макро-F1 власної моделі: {100 * f1_score(yte, pred, average='macro'):.1f} %")

out()
out("Найчастіші помилки власної моделі (клас -> що передбачено)")
for ci, c in enumerate(classes):
    idx = np.where(yte == ci)[0]
    wrong = collections.Counter(classes[p] for p in pred[idx] if p != ci)
    if wrong and (pred[idx] == ci).mean() < 0.9:
        out(f"  {c:7s} {wrong.most_common(3)}")

with open(OUT, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["cls", "split_mode", "train_files", "test_files", "test_windows",
                "own_acc", "magika_acc", "magika_unknown"])
    w.writerows(rows)
REPORT.write_text("\n".join(lines), encoding="utf-8")
out(f"\nЗвіт: {REPORT}")