import collections
import csv
import pathlib
import random
import sys

import numpy as np

BASE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from src.triage.fragment import WIN, FragmentClassifier, feats
from src.triage.triage import MAP, _magika

N_IMG, STEP, TOL, SMOOTH, SEED = 100, 2048, 8192, 5, 42
CLS = ["pdf", "ole2", "html", "txt", "csv", "xml", "gif", "jpg", "gz", "rtf"]
TEXT = {"txt", "csv"}
rng = random.Random(SEED)

pool = collections.defaultdict(list)
with open(BASE / "results" / "govdocs_test.csv", encoding="utf-8", newline="") as fh:
    for r in csv.DictReader(fh):
        if r["format"] in CLS and int(r["size"]) >= 16384:
            pool[r["format"]].append(r["src"])
classes = [c for c in CLS if len(pool[c]) >= 3]
print("Класи у складених образах:", {c: len(pool[c]) for c in classes})


def make_image():
    seq, prev = [], None
    for _ in range(rng.randint(3, 6)):
        c = rng.choice([x for x in classes if x != prev])
        data = pathlib.Path(rng.choice(pool[c])).read_bytes()
        seq.append((c, data[:rng.randint(16384, min(len(data), 131072))]))
        prev = c
    return seq


def smooth(labels):
    h = SMOOTH // 2
    return [collections.Counter(labels[max(0, i - h):i + h + 1]).most_common(1)[0][0]
            for i in range(len(labels))]


def fam(c):
    return "text" if c in TEXT else c


def match(true_b, pred_b):
    used, tp = set(), 0
    for t in true_b:
        cand = [(abs(p - t), j) for j, p in enumerate(pred_b) if j not in used]
        if cand:
            d, j = min(cand)
            if d <= TOL:
                used.add(j)
                tp += 1
    return tp


fc = FragmentClassifier()
mg = _magika()
stat = {m: dict(ok=0, okf=0, bins=0, tp=0, np=0, nt=0) for m in ("власна", "Magika")}
for _ in range(N_IMG):
    seq = make_image()
    data = b"".join(d for _, d in seq)
    n = len(data)
    ends, s = [], 0
    for c, d in seq:
        s += len(d)
        ends.append((s, c))
    true_b = [e for e, _ in ends[:-1]]
    nb = (n + STEP - 1) // STEP
    truth = []
    for k in range(nb):
        mid = min(k * STEP + STEP // 2, n - 1)
        truth.append(next(c for e, c in ends if mid < e))
    wins = []
    for k in range(nb):
        o = min(max(k * STEP - (WIN - STEP) // 2, 0), max(n - WIN, 0))
        wins.append(data[o:o + WIN])
    own = [fc.classes[i] for i in fc.model.predict_proba(
        np.array([feats(w) for w in wins])).argmax(1)]
    mgl = []
    for w in wins:
        r = mg.identify_bytes(w)
        mgl.append((MAP.get(str(r.output.label)) if r.ok else None) or "?")
    for name, lab in (("власна", own), ("Magika", mgl)):
        sm = smooth(lab)
        st = stat[name]
        st["bins"] += nb
        st["ok"] += sum(a == b for a, b in zip(sm, truth))
        st["okf"] += sum(fam(a) == fam(b) for a, b in zip(sm, truth))
        pred_b = [k * STEP for k in range(1, nb) if sm[k] != sm[k - 1]]
        st["tp"] += match(true_b, pred_b)
        st["np"] += len(pred_b)
        st["nt"] += len(true_b)

print(f"\nОбразів: {N_IMG}, крок {STEP} Б, вікно {WIN} Б, допуск меж {TOL} Б, згладжування {SMOOTH}")
print(f"{'метод':8s}{'байти, %':>10s}{'родина, %':>11s}{'точн. меж':>11s}{'повнота':>9s}{'F1':>7s}{'меж/істинних':>14s}")
for name, st in stat.items():
    p = st["tp"] / st["np"] if st["np"] else 0.0
    rc = st["tp"] / st["nt"]
    f1 = 2 * p * rc / (p + rc) if p + rc else 0.0
    print(f"{name:8s}{100 * st['ok'] / st['bins']:10.1f}{100 * st['okf'] / st['bins']:11.1f}"
          f"{100 * p:11.1f}{100 * rc:9.1f}{f1:7.2f}{st['np']:8d}/{st['nt']:<5d}")