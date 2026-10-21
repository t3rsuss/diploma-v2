import collections
import csv
import hashlib
import pathlib
import random
import shutil
import sys

import joblib
import lightgbm as lgb
import numpy as np

BASE = pathlib.Path(r"C:\Users\vlad\Desktop\diploma-v2")
sys.path.insert(0, str(BASE))
from src.triage.fragment import MODEL_PATH, check_content, feats, windows

MANIFEST = BASE / "results" / "corpus_manifest_frozen.csv"
CORPUS = BASE / "data" / "corpus"
EXT = BASE / "data" / "ext_corpus"
GD_DEV = BASE / "results" / "govdocs_dev.csv"
DIRMAP = {"conf": "ini", "cfg": "ini"}
TRAIN_WIN, MIN_FILES, EXT_PER, GD_PER, SEED = 40, 20, 60, 100, 42
rng = random.Random(SEED)

files, seen = [], set()
src_count = collections.Counter()


def add(cls, data, source):
    h = hashlib.sha256(data).hexdigest()
    if h in seen:
        return
    seen.add(h)
    files.append((cls, data))
    src_count[source] += 1


with open(MANIFEST, encoding="utf-8", newline="") as fh:
    rows = list(csv.DictReader(fh))
by = collections.defaultdict(list)
for r in rows:
    by[r["format"]].append(r)
win_classes = sorted(c for c, v in by.items() if len(v) >= MIN_FILES)
for c in win_classes:
    for it in by[c]:
        ext = it["ext"]
        p = CORPUS / c / (it["sha256"][:12] + ("." + ext if ext else ""))
        add(c, p.read_bytes(), "Windows")

ext_n = collections.Counter()
for d in sorted(EXT.iterdir()):
    cls = DIRMAP.get(d.name, d.name)
    if cls not in win_classes:
        continue
    for p in sorted(d.iterdir()):
        b = p.read_bytes()
        if len(b) < 512 or ext_n[cls] >= EXT_PER or not check_content(cls, b):
            continue
        ext_n[cls] += 1
        add(cls, b, "Ubuntu")

with open(GD_DEV, encoding="utf-8", newline="") as fh:
    gd = list(csv.DictReader(fh))
gby = collections.defaultdict(list)
for r in gd:
    gby[r["format"]].append(r)
for cls, lst in gby.items():
    rng.shuffle(lst)
    for r in lst[:GD_PER]:
        add(cls, pathlib.Path(r["src"]).read_bytes(), "GovDocs")

classes = sorted({c for c, _ in files})
print("Джерела:", dict(src_count))
print("Файлів за класами:", dict(collections.Counter(c for c, _ in files)))

X, y = [], []
for cls, data in files:
    r = random.Random(int(hashlib.sha256(data).hexdigest()[:8], 16) + 1)
    for w in windows(data, TRAIN_WIN, r):
        X.append(feats(w))
        y.append(classes.index(cls))
print(f"Вікон: {len(y)}, ознак: {len(X[0])}, класів: {len(classes)}", flush=True)

clf = lgb.LGBMClassifier(n_estimators=300, learning_rate=0.08, num_leaves=31,
                         subsample=0.8, subsample_freq=1, colsample_bytree=0.5,
                         class_weight="balanced", random_state=SEED, verbose=-1, n_jobs=-1)
clf.fit(np.array(X), np.array(y))

backup = MODEL_PATH.with_name("fragment_clf_v1.joblib")
if MODEL_PATH.exists() and not backup.exists():
    shutil.copyfile(MODEL_PATH, backup)
joblib.dump({"model": clf, "classes": classes}, MODEL_PATH)
print("Класи:", ", ".join(classes))
print("Збережено:", MODEL_PATH, MODEL_PATH.stat().st_size // 1024, "КБ")