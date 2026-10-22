import collections
import csv
import hashlib
import pathlib
import random
import sys

import joblib
import lightgbm as lgb
import numpy as np

BASE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from src.triage.fragment import MODEL_PATH, check_content, feats, windows

MANIFEST = BASE / "results" / "corpus_manifest_frozen.csv"
CORPUS = BASE / "data" / "corpus"
EXT = BASE / "data" / "ext_corpus"
DIRMAP = {"conf": "ini", "cfg": "ini"}
TRAIN_WIN, MIN_FILES, EXT_PER, SEED = 40, 20, 60, 42

with open(MANIFEST, encoding="utf-8", newline="") as fh:
    rows = list(csv.DictReader(fh))
by = collections.defaultdict(list)
for r in rows:
    by[r["format"]].append(r)
classes = sorted(c for c, v in by.items() if len(v) >= MIN_FILES)

files = []
for ci, c in enumerate(classes):
    for it in by[c]:
        ext = it["ext"]
        p = CORPUS / c / (it["sha256"][:12] + ("." + ext if ext else ""))
        files.append((ci, p.read_bytes()))
n_win = len(files)
seen = set()
ext_n = collections.Counter()
for d in sorted(EXT.iterdir()):
    cls = DIRMAP.get(d.name, d.name)
    if cls not in classes:
        continue
    for p in sorted(d.iterdir()):
        b = p.read_bytes()
        h = hashlib.sha256(b).hexdigest()
        if len(b) < 512 or h in seen or ext_n[cls] >= EXT_PER or not check_content(cls, b):
            continue
        seen.add(h)
        ext_n[cls] += 1
        files.append((classes.index(cls), b))
print(f"Файлів Windows: {n_win}, з Ubuntu: {len(files) - n_win}")

X, y = [], []
for i, (ci, data) in enumerate(files):
    r = random.Random(int(hashlib.sha256(data).hexdigest()[:8], 16) + 1)
    for w in windows(data, TRAIN_WIN, r):
        X.append(feats(w))
        y.append(ci)
print(f"Вікон: {len(y)}, ознак: {len(X[0])}")
clf = lgb.LGBMClassifier(n_estimators=300, learning_rate=0.08, num_leaves=31,
                         subsample=0.8, subsample_freq=1, colsample_bytree=0.5,
                         class_weight="balanced", random_state=SEED, verbose=-1, n_jobs=-1)
clf.fit(np.array(X), np.array(y))
MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
joblib.dump({"model": clf, "classes": classes}, MODEL_PATH)
print("Класи:", ", ".join(classes))
print("Модель збережено:", MODEL_PATH, MODEL_PATH.stat().st_size // 1024, "КБ")