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

N_TUNE, N_EVAL, STEP, TOL, SMOOTH, SEED = 60, 100, 2048, 8192, 5, 42
LAMS = [1, 2, 4, 6, 8, 12, 16, 24]
CLS = ["pdf", "ole2", "html", "txt", "csv", "xml", "gif", "jpg", "gz", "rtf"]
TEXT = {"txt", "csv"}

raw = collections.defaultdict(list)
with open(BASE / "results" / "govdocs_test.csv", encoding="utf-8", newline="") as fh:
    for r in csv.DictReader(fh):
        if r["format"] in CLS and int(r["size"]) >= 16384:
            raw[r["format"]].append(r["src"])
pools = {"tune": {}, "eval": {}}
for c, lst in raw.items():
    lst = sorted(lst)
    if len(lst[0::2]) >= 2 and len(lst[1::2]) >= 2:
        pools["tune"][c], pools["eval"][c] = lst[0::2], lst[1::2]
print("Класи:", {c: (len(pools["tune"][c]), len(pools["eval"][c])) for c in pools["tune"]})

fc = FragmentClassifier()
mg = _magika()


def fam(c):
    return "text" if c in TEXT else c


def build(rng, pool, n_img):
    classes = list(pool)
    out = []
    for _ in range(n_img):
        seq, prev = [], None
        for _ in range(rng.randint(3, 6)):
            c = rng.choice([x for x in classes if x != prev])
            d = pathlib.Path(rng.choice(pool[c])).read_bytes()
            seq.append((c, d[:rng.randint(16384, min(len(d), 131072))]))
            prev = c
        data = b"".join(d for _, d in seq)
        n = len(data)
        ends, s = [], 0
        for c, d in seq:
            s += len(d)
            ends.append((s, c))
        nb = (n + STEP - 1) // STEP
        truth = [next(c for e, c in ends if min(k * STEP + STEP // 2, n - 1) < e) for k in range(nb)]
        wins = [data[min(max(k * STEP - (WIN - STEP) // 2, 0), max(n - WIN, 0)):][:WIN] for k in range(nb)]
        out.append(dict(truth=truth, true_b=[e for e, _ in ends[:-1]], wins=wins))
    for im in out:
        p = fc.model.predict_proba(np.array([feats(w) for w in im["wins"]]))
        im["lp"] = np.log(p + 1e-6)
    return out


def smooth(labels):
    h = SMOOTH // 2
    return [collections.Counter(labels[max(0, i - h):i + h + 1]).most_common(1)[0][0]
            for i in range(len(labels))]


def viterbi(lp, lam):
    T, K = lp.shape
    dp = lp[0].copy()
    back = np.zeros((T, K), dtype=int)
    for t in range(1, T):
        bp = int(dp.argmax())
        sw = dp[bp] - lam
        stay = dp >= sw
        back[t] = np.where(stay, np.arange(K), bp)
        dp = np.where(stay, dp, sw) + lp[t]
    path = [int(dp.argmax())]
    for t in range(T - 1, 0, -1):
        path.append(int(back[t][path[-1]]))
    return [fc.classes[i] for i in path[::-1]]


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


def score(images, labeler):
    s = dict(ok=0, okf=0, bins=0, tp=0, np=0, nt=0)
    for im in images:
        lab = labeler(im)
        tr = im["truth"]
        s["bins"] += len(tr)
        s["ok"] += sum(a == b for a, b in zip(lab, tr))
        s["okf"] += sum(fam(a) == fam(b) for a, b in zip(lab, tr))
        pb = [k * STEP for k in range(1, len(lab)) if lab[k] != lab[k - 1]]
        s["tp"] += match(im["true_b"], pb)
        s["np"] += len(pb)
        s["nt"] += len(im["true_b"])
    p = s["tp"] / s["np"] if s["np"] else 0.0
    r = s["tp"] / s["nt"]
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return 100 * s["ok"] / s["bins"], 100 * s["okf"] / s["bins"], 100 * p, 100 * r, f1, s["np"], s["nt"]


def show(name, v):
    print(f"{name:22s}{v[0]:9.1f}{v[1]:10.1f}{v[2]:10.1f}{v[3]:9.1f}{v[4]:7.2f}{v[5]:7d}/{v[6]:<5d}")


head = f"{'метод':22s}{'байти,%':>9s}{'родина,%':>10s}{'точн.меж':>10s}{'повнота':>9s}{'F1':>7s}{'меж/істинних':>14s}"
tune = build(random.Random(SEED + 1), pools["tune"], N_TUNE)
print("\nПідбір λ на парних файлах\n" + head)
res = {}
for lam in LAMS:
    res[lam] = score(tune, lambda im, l=lam: viterbi(im["lp"], l))
    show(f"Вітербі λ={lam}", res[lam])
best = max(LAMS, key=lambda l: (res[l][4], res[l][0]))
print("\nОбрано λ =", best)

ev = build(random.Random(SEED), pools["eval"], N_EVAL)
for im in ev:
    ml = []
    for w in im["wins"]:
        r = mg.identify_bytes(w)
        ml.append((MAP.get(str(r.output.label)) if r.ok else None) or "?")
    im["mg"] = ml
print("\nОцінка на непарних файлах\n" + head)
show("власна, argmax", score(ev, lambda im: [fc.classes[i] for i in im["lp"].argmax(1)]))
show("власна, згладж. 5", score(ev, lambda im: smooth([fc.classes[i] for i in im["lp"].argmax(1)])))
show(f"власна, Вітербі λ={best}", score(ev, lambda im: viterbi(im["lp"], best)))
show("Magika, згладж. 5", score(ev, lambda im: smooth(im["mg"])))