import collections
import contextlib
import csv
import io
import pathlib
import random
import runpy
import sys

import joblib
import numpy as np

BASE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from src.triage.fragment import feats, windows

with contextlib.redirect_stdout(io.StringIO()):
    g = runpy.run_path(str(BASE / "experiments" / "e8_viterbi.py"), run_name="e8")
fc, viterbi, score, ev = g["fc"], g["viterbi"], g["score"], g["ev"]
old = joblib.load(BASE / "src" / "models" / "fragment_clf_g1.joblib")
if list(old["classes"]) != list(fc.classes):
    raise SystemExit("Набори класів старої і нової моделей різні")
LAM, TEST_WIN, MIN_FILES = 24, 5, 10
models = {"до": old["model"], "після": fc.model}

rng = random.Random(42)
with open(BASE / "results" / "govdocs_test.csv", encoding="utf-8", newline="") as fh:
    rows = [r for r in csv.DictReader(fh) if r["format"] != "other"]
nfiles = collections.Counter(r["format"] for r in rows)
true, X = [], []
for r in rows:
    data = pathlib.Path(r["src"]).read_bytes()
    for w in windows(data, TEST_WIN, rng):
        true.append(r["format"])
        X.append(feats(w))
X = np.array(X)
pred = {k: [fc.classes[i] for i in m.predict_proba(X).argmax(1)] for k, m in models.items()}


def ok(t, p):
    return p == t or (t == "log" and p == "txt")


print(f"Фрагменти GovDocs-test: {len(true)} вікон, {len(rows)} файлів")
print(f"{'клас':7s}{'файлів':>7s}{'до, %':>9s}{'після, %':>10s}")
macro = {k: [] for k in models}
for c in sorted(nfiles):
    idx = [i for i, t in enumerate(true) if t == c]
    v = {k: 100 * np.mean([ok(true[i], pred[k][i]) for i in idx]) for k in models}
    star = "*" if nfiles[c] < MIN_FILES else " "
    print(f"{c:7s}{nfiles[c]:6d}{star}{v['до']:9.1f}{v['після']:10.1f}")
    if nfiles[c] >= MIN_FILES:
        for k in models:
            macro[k].append(v[k])
print(f"Макро ({len(macro['до'])} класів): до {np.mean(macro['до']):.1f}, після {np.mean(macro['після']):.1f}\n")

for im in ev:
    im["lp1"] = np.log(old["model"].predict_proba(np.array([feats(w) for w in im["wins"]])) + 1e-6)
print(f"Складені образи, Вітербі λ={LAM}")
print(f"{'модель':8s}{'байти,%':>9s}{'точн.меж':>10s}{'повнота':>9s}{'F1':>7s}")
for name, key in (("до", "lp1"), ("після", "lp")):
    v = score(ev, lambda im, k=key: viterbi(im[k], LAM))
    print(f"{name:8s}{v[0]:9.1f}{v[2]:10.1f}{v[3]:9.1f}{v[4]:7.2f}")