import contextlib
import io
import pathlib
import random
import runpy
import statistics

import numpy as np

BASE = pathlib.Path(__file__).resolve().parents[1]
with contextlib.redirect_stdout(io.StringIO()):
    g = runpy.run_path(str(BASE / "experiments" / "e8_viterbi.py"), run_name="e8")
viterbi, tune, STEP, score, build, pools, fc = (g[k] for k in ("viterbi", "tune", "STEP", "score", "build", "pools", "fc"))
LAM = 24
BONUS = (0, 6, 12, 18, 24, 36)
SEEDS = (101, 102, 103, 104, 105)
N_SEED = 60

MAGIC = {
    "pdf": [b"%PDF-"], "ole2": [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"], "gif": [b"GIF8"],
    "jpg": [b"\xff\xd8\xff"], "gz": [b"\x1f\x8b\x08"], "rtf": [b"{\\rtf"],
    "html": [b"<!DOCTYPE", b"<!doctype", b"<html", b"<HTML"], "xml": [b"<?xml"],
}
CIDX = {c: fc.classes.index(c) for c in MAGIC}


def restore(im):
    n = 0
    spans = []
    for k, w in enumerate(im["wins"]):
        o = max(k * STEP - 1024, 0)
        spans.append((o, w))
        n = max(n, o + len(w))
    buf = bytearray(n)
    for o, w in spans:
        buf[o:o + len(w)] = w
    return bytes(buf)


def anchors(im):
    if "anch" not in im:
        data = restore(im)
        found = []
        for c, sigs in MAGIC.items():
            for s in sigs:
                i = data.find(s)
                while i != -1:
                    found.append((i // STEP, CIDX[c]))
                    i = data.find(s, i + 1)
        im["anch"] = found
    return im["anch"]


def labeler(B):
    def f(im):
        lp = im["lp"].copy()
        if B:
            for k, i in anchors(im):
                if k < len(lp):
                    lp[k, i] += B
        return viterbi(lp, LAM)
    return f


print(f"Підбір бонусу B при λ={LAM} (парні файли)")
res = {}
for B in BONUS:
    res[B] = score(tune, labeler(B))
    v = res[B]
    print(f"  B={B:3d}: байти {v[0]:.1f}, точн. меж {v[2]:.1f}, повнота {v[3]:.1f}, F1 {v[4]:.2f}")
best = max(BONUS, key=lambda b: (round(res[b][4], 2), res[b][0]))
print("Обрано B =", best, "\n")

rows = {"Вітербі": [], f"Вітербі + якорі (B={best})": []}
for sd in SEEDS:
    imgs = build(random.Random(sd), pools["eval"], N_SEED)
    rows["Вітербі"].append(score(imgs, labeler(0)))
    rows[f"Вітербі + якорі (B={best})"].append(score(imgs, labeler(best)))
print(f"Непарні файли, {len(SEEDS)} зерен по {N_SEED} образів: середнє ± ст. відхилення")
print(f"{'метод':26s}{'байти, %':>16s}{'точн. меж':>16s}{'повнота':>16s}{'F1':>14s}")
for name, vs in rows.items():
    def ms(i):
        xs = [v[i] for v in vs]
        return f"{statistics.mean(xs):.1f} ± {statistics.pstdev(xs):.1f}"
    xs = [v[4] for v in vs]
    print(f"{name:26s}{ms(0):>16s}{ms(2):>16s}{ms(3):>16s}{statistics.mean(xs):9.2f} ± {statistics.pstdev(xs):.2f}")