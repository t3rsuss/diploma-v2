import pathlib
import pickle

import lightgbm as lgb
import numpy as np

BASE = pathlib.Path(r"C:\Users\vlad\Desktop\diploma-v2")
data_all = pickle.load(open(BASE / "results" / "e13_cache.pkl", "rb"))
fmts = [c for c in data_all if data_all[c]]
SEED, TOLS = 42, (1, 4)
METHODS = ["усе-наповн.", "голова K", "ентропія", "модель", "модель-без-поз."]


def stack(names):
    X = np.vstack([f[l >= 0] for c in names for _, f, l in data_all[c]])
    y = np.concatenate([l[l >= 0] for c in names for _, f, l in data_all[c]])
    return X, y


def f1_struct(y, p):
    tp = ((y == 0) & (p == 0)).sum()
    fp = ((y == 1) & (p == 0)).sum()
    fn = ((y == 0) & (p == 1)).sum()
    pr = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    return 2 * pr * rc / (pr + rc) if pr + rc else 0.0


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


def prf(tp, npred, nt):
    p = tp / npred if npred else 0.0
    r = tp / nt if nt else 0.0
    return p, r, (2 * p * r / (p + r) if p + r else 0.0)


res = {}
for held in fmts:
    Xtr, ytr = stack([c for c in fmts if c != held])
    bestk = max(range(0, 8), key=lambda k: f1_struct(ytr, np.where(Xtr[:, -4] < k, 0, 1)))
    thr = max(np.arange(3.0, 8.0, 0.1), key=lambda t: f1_struct(ytr, np.where(Xtr[:, 0] < t, 0, 1)))
    kw = dict(n_estimators=200, num_leaves=15, learning_rate=0.08, subsample=0.8, subsample_freq=1,
              colsample_bytree=0.7, class_weight="balanced", random_state=SEED, verbose=-1, n_jobs=-1)
    m_all = lgb.LGBMClassifier(**kw).fit(Xtr, ytr)
    m_np = lgb.LGBMClassifier(**kw).fit(Xtr[:, :-4], ytr)
    pred = {
        "усе-наповн.": lambda f: np.ones(len(f), int),
        "голова K": lambda f: np.where(f[:, -4] < bestk, 0, 1),
        "ентропія": lambda f: np.where(f[:, 0] < thr, 0, 1),
        "модель": lambda f: m_all.predict(f).astype(int),
        "модель-без-поз.": lambda f: m_np.predict(f[:, :-4]).astype(int),
    }
    blk = {m: ([], []) for m in METHODS}
    bnd = {m: {t: [0, 0, 0] for t in TOLS} for m in METHODS}
    share = [0, 0]
    for _, f, l in data_all[held]:
        v = l >= 0
        share[0] += (l[v] == 0).sum()
        share[1] += v.sum()
        tb = boundaries(l)
        for m in METHODS:
            p = pred[m](f)
            blk[m][0].append(l[v])
            blk[m][1].append(p[v])
            pb = boundaries(np.where(v, p if m in ("усе-наповн.", "голова K") else smooth(p), -1))
            for t in TOLS:
                bnd[m][t][0] += match(tb, pb, t)
                bnd[m][t][1] += len(pb)
                bnd[m][t][2] += len(tb)
    res[held] = dict(share=100 * share[0] / share[1], K=bestk, thr=thr,
                     sf1={m: f1_struct(np.concatenate(blk[m][0]), np.concatenate(blk[m][1])) for m in METHODS},
                     bf1={t: {m: prf(*bnd[m][t])[2] for m in METHODS} for t in TOLS})


def table(title, getter):
    print(f"\n{title}")
    print(f"{'формат':8s}{'структ.,%':>10s}" + "".join(f"{m:>17s}" for m in METHODS))
    acc = {m: [] for m in METHODS}
    for h in fmts:
        vals = getter(res[h])
        print(f"{h:8s}{res[h]['share']:10.1f}" + "".join(f"{vals[m]:17.2f}" for m in METHODS))
        for m in METHODS:
            acc[m].append(vals[m])
    print(f"{'макро':8s}{'':10s}" + "".join(f"{np.mean(acc[m]):17.2f}" for m in METHODS))


table("F1 класу «структура» (за блоками по 256 Б)", lambda r: r["sf1"])
for t in TOLS:
    table(f"F1 меж між структурою і наповненням, допуск ±{t} блок(и)", lambda r, t=t: r["bf1"][t])
print("\nПідібрані параметри:", {h: (res[h]["K"], round(res[h]["thr"], 1)) for h in fmts})