import collections
import contextlib
import io
import pathlib
import runpy
import statistics

BASE = pathlib.Path(r"C:\Users\vlad\Desktop\diploma-v2")
with contextlib.redirect_stdout(io.StringIO()):
    g = runpy.run_path(str(BASE / "experiments" / "e8_viterbi.py"), run_name="e8")
viterbi, tune, ev, STEP, score, res = (g[k] for k in ("viterbi", "tune", "ev", "STEP", "score", "res"))

print("Розширена сітка λ (парні файли)")
for lam in (32, 48, 64, 96):
    res[lam] = score(tune, lambda im, l=lam: viterbi(im["lp"], l))
    print(f"  λ={lam:3d}: байти {res[lam][0]:.1f}, точн. {res[lam][2]:.1f}, повнота {res[lam][3]:.1f}, F1 {res[lam][4]:.2f}")
best = max(res, key=lambda l: res[l][4])
print(f"Обрано λ = {best} (макс. F1 на парних {res[best][4]:.3f})\n")

MAGIC = {
    "pdf": [b"%PDF-"], "ole2": [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"], "gif": [b"GIF8"],
    "jpg": [b"\xff\xd8\xff"], "gz": [b"\x1f\x8b\x08"], "rtf": [b"{\\rtf"],
    "html": [b"<!DOCTYPE", b"<!doctype", b"<html", b"<HTML"], "xml": [b"<?xml"],
}
R = 6144


def restore(im):
    spans = []
    n = 0
    for k, w in enumerate(im["wins"]):
        o = max(k * STEP - 1024, 0)
        spans.append((o, w))
        n = max(n, o + len(w))
    buf = bytearray(n)
    for o, w in spans:
        buf[o:o + len(w)] = w
    return bytes(buf)


def snap(data, b, cls):
    sigs = MAGIC.get(cls)
    if not sigs:
        return b
    lo, hi = max(0, b - R), min(len(data), b + R)
    seg = data[lo:hi]
    cand = []
    for s in sigs:
        i = seg.find(s)
        while i != -1:
            cand.append(lo + i)
            i = seg.find(s, i + 1)
    return min(cand, key=lambda p: abs(p - b)) if cand else b


def match(true_b, pred_b, tol):
    used, errs = set(), []
    for t in true_b:
        cand = [(abs(p - t), j) for j, p in enumerate(pred_b) if j not in used]
        if cand:
            d, j = min(cand)
            if d <= tol:
                used.add(j)
                errs.append(d)
    return errs


TOLS = (512, 2048, 8192)
agg = {m: {t: dict(tp=0, np=0, nt=0, errs=[]) for t in TOLS} for m in ("без уточнення", "з сигнатурами")}
cls_ok, cls_n, conf = collections.Counter(), collections.Counter(), collections.Counter()
for im in ev:
    lab = viterbi(im["lp"], best)
    data = restore(im)
    for a, b in zip(im["truth"], lab):
        cls_n[a] += 1
        cls_ok[a] += a == b
        if a != b:
            conf[(a, b)] += 1
    raw = [(k * STEP, lab[k]) for k in range(1, len(lab)) if lab[k] != lab[k - 1]]
    snapped = [(snap(data, b, c), c) for b, c in raw]
    for m, pb in (("без уточнення", [b for b, _ in raw]), ("з сигнатурами", [b for b, _ in snapped])):
        for t in TOLS:
            errs = match(im["true_b"], pb, t)
            a = agg[m][t]
            a["tp"] += len(errs)
            a["np"] += len(pb)
            a["nt"] += len(im["true_b"])
            a["errs"] += errs

print(f"Межі при λ={best}, непарні файли")
print(f"{'метод':16s}{'допуск, Б':>10s}{'точн.':>8s}{'повнота':>9s}{'F1':>7s}{'мед. похибка, Б':>17s}")
for m in agg:
    for t in TOLS:
        a = agg[m][t]
        p = a["tp"] / a["np"] if a["np"] else 0.0
        r = a["tp"] / a["nt"]
        f1 = 2 * p * r / (p + r) if p + r else 0.0
        med = statistics.median(a["errs"]) if a["errs"] else float("nan")
        print(f"{m:16s}{t:10d}{100 * p:8.1f}{100 * r:9.1f}{f1:7.2f}{med:17.0f}")

print("\nТочність за байтами по класах (істинний клас)")
for c in sorted(cls_n, key=lambda x: -cls_n[x]):
    print(f"  {c:6s} бінів {cls_n[c]:6d}  {100 * cls_ok[c] / cls_n[c]:5.1f} %")
print("\nНайчастіші плутанини (істинний -> передбачений)")
for (a, b), n in conf.most_common(10):
    print(f"  {a:6s} -> {b:6s} {n:5d} ({100 * n / sum(cls_n.values()):.1f} % усіх бінів)")