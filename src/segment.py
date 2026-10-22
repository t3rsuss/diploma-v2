import numpy as np

from src.triage.fragment import WIN, feats

STEP, LAM, BONUS, SNAP_R, MAX_BINS = 2048, 24.0, 24.0, 6144, 8192
MAGIC = {
    "pdf": [b"%PDF-"], "ole2": [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"], "gif": [b"GIF8"],
    "jpg": [b"\xff\xd8\xff"], "gz": [b"\x1f\x8b\x08"], "rtf": [b"{\\rtf"],
    "html": [b"<!DOCTYPE", b"<!doctype", b"<html", b"<HTML"], "xml": [b"<?xml"],
}


def _occurrences(data, sig):
    i = data.find(sig)
    while i != -1:
        yield i
        i = data.find(sig, i + 1)


def _viterbi(lp, lam):
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
    return path[::-1]


def _snap(data, b, cls):
    sigs = MAGIC.get(cls)
    if not sigs:
        return b
    lo, hi = max(0, b - SNAP_R), min(len(data), b + SNAP_R)
    seg = data[lo:hi]
    cand = [lo + i for s in sigs for i in _occurrences(seg, s)]
    return min(cand, key=lambda p: abs(p - b)) if cand else b


def segment(data, fc, lam=LAM, bonus=BONUS, snap=True):
    n = len(data)
    if n == 0:
        return []
    step = STEP
    if (n + STEP - 1) // STEP > MAX_BINS:
        step = (n // MAX_BINS // 512 + 1) * 512
    nb = (n + step - 1) // step
    offs = [min(max(k * step - (WIN - step) // 2, 0), max(n - WIN, 0)) for k in range(nb)]
    p = fc.model.predict_proba(np.array([feats(data[o:o + WIN]) for o in offs]))
    lp = np.log(p + 1e-6)
    if bonus:
        for c, sigs in MAGIC.items():
            if c not in fc.classes:
                continue
            ci = fc.classes.index(c)
            for s in sigs:
                for pos in _occurrences(data, s):
                    if pos // step < nb:
                        lp[pos // step, ci] += bonus
    path = _viterbi(lp, lam)
    segs, start = [], 0
    for k in range(1, nb + 1):
        if k == nb or path[k] != path[k - 1]:
            segs.append([start * step, min(k * step, n), path[start]])
            start = k
    if snap:
        for i in range(1, len(segs)):
            b = _snap(data, segs[i][0], fc.classes[segs[i][2]])
            if segs[i - 1][0] < b < segs[i][1]:
                segs[i][0] = segs[i - 1][1] = b
    out = []
    for s, e, ci in segs:
        k0, k1 = s // step, min((e - 1) // step + 1, nb)
        out.append(dict(start=s, end=e, length=e - s, cls=fc.classes[ci],
                        conf=float(p[k0:k1, ci].mean())))
    return out