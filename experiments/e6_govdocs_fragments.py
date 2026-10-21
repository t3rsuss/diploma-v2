import collections
import csv
import pathlib
import random
import sys

import numpy as np

BASE = pathlib.Path(r"C:\Users\vlad\Desktop\diploma-v2")
sys.path.insert(0, str(BASE))
from src.triage.fragment import FragmentClassifier, feats, windows
from src.triage.triage import MAP, THETA, _magika

TEST_WIN, MIN_FILES, SEED = 5, 10, 42
TEXT = {"txt", "log", "ini", "csv"}
EXTRA = {"rdf": "xml", "svg": "xml", "kml": "xml", "xhtml": "html"}
rng = random.Random(SEED)

with open(BASE / "results" / "govdocs_test.csv", encoding="utf-8", newline="") as fh:
    rows = [r for r in csv.DictReader(fh) if r["format"] != "other"]
nfiles = collections.Counter(r["format"] for r in rows)
fc = FragmentClassifier()
mg = _magika()


def fam(c):
    return "text" if c in TEXT else c


tests = []
for r in rows:
    data = pathlib.Path(r["src"]).read_bytes()
    for w in windows(data, TEST_WIN, rng):
        tests.append((r["format"], w))
true = [t for t, _ in tests]
proba = fc.model.predict_proba(np.array([feats(w) for _, w in tests]))
own = [fc.classes[i] for i in proba.argmax(1)]
conf = proba.max(1)
mcls, mscore, mlab = [], [], []
for _, w in tests:
    r = mg.identify_bytes(w)
    lab = str(r.output.label) if r.ok else "error"
    mlab.append(lab)
    mscore.append(float(r.score) if r.ok else 0.0)
    mcls.append(MAP.get(lab) or EXTRA.get(lab))
hyb = [m if (m and s >= THETA) else o for m, s, o in zip(mcls, mscore, own)]
print(f"Вікон: {len(tests)}, файлів: {len(rows)}")


def acc(pred, idx, family):
    if family:
        return np.mean([fam(pred[i]) == fam(true[i]) for i in idx])
    return np.mean([pred[i] == true[i] or (true[i] == "log" and pred[i] == "txt") for i in idx])


mg_pred = [m or "?" for m in mcls]
print(f"{'клас':7s}{'файлів':>7s}{'вікон':>6s} | {'власна':>7s}{'Magika':>8s}{'гібрид':>8s} | "
      f"{'власна':>7s}{'Magika':>8s}{'гібрид':>8s}  (ліворуч строго, праворуч за родиною)")
agg = collections.defaultdict(list)
for c in sorted(nfiles):
    idx = [i for i, t in enumerate(true) if t == c]
    vals = [acc(p, idx, f) for f in (False, True) for p in (own, mg_pred, hyb)]
    star = "*" if nfiles[c] < MIN_FILES else " "
    print(f"{c:7s}{nfiles[c]:6d}{star}{len(idx):6d} | " +
          "".join(f"{100 * v:8.1f}" for v in vals[:3]) + " | " +
          "".join(f"{100 * v:8.1f}" for v in vals[3:]))
    if nfiles[c] >= MIN_FILES:
        for k, v in enumerate(vals):
            agg[k].append(v)
m = [100 * np.mean(agg[k]) for k in range(6)]
print(f"\nМакро за класами з n >= {MIN_FILES} ({len(agg[0])} класів)")
print(f"  строго:        власна {m[0]:.1f}, Magika {m[1]:.1f}, гібрид {m[2]:.1f}")
print(f"  за родиною:    власна {m[3]:.1f}, Magika {m[4]:.1f}, гібрид {m[5]:.1f}")
print("\nОхоплення і точність серед відповідей, макро (строго), %")
cls_big = [c for c in nfiles if nfiles[c] >= MIN_FILES]
for t in (0.0, 0.7, 0.9):
    cov, ac = [], []
    for c in cls_big:
        idx = np.array([i for i, x in enumerate(true) if x == c])
        keep = idx[conf[idx] >= t]
        cov.append(len(keep) / len(idx))
        ac.append(np.mean([own[i] == c for i in keep]) if len(keep) else 0.0)
    print(f"  власна {t}: охоплення {100 * np.mean(cov):.1f}, точність {100 * np.mean(ac):.1f}")
cov, ac = [], []
for c in cls_big:
    idx = [i for i, x in enumerate(true) if x == c]
    ans = [i for i in idx if mcls[i] and mscore[i] >= THETA]
    cov.append(len(ans) / len(idx))
    ac.append(np.mean([mcls[i] == c for i in ans]) if ans else 0.0)
print(f"  Magika: охоплення {100 * np.mean(cov):.1f}, точність {100 * np.mean(ac):.1f}")