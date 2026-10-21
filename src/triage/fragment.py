import json
import pathlib
import random
import xml.etree.ElementTree as ET
import zlib

import joblib
import numpy as np

WIN = 4096
ROOT = pathlib.Path(__file__).resolve().parents[2]
MODEL_PATH = ROOT / "src" / "models" / "fragment_clf.joblib"
SIG = {
    "png": lambda b: b[:8] == b"\x89PNG\r\n\x1a\n",
    "jpg": lambda b: b[:3] == b"\xff\xd8\xff",
    "gif": lambda b: b[:6] in (b"GIF87a", b"GIF89a"),
    "ico": lambda b: b[:4] == b"\x00\x00\x01\x00",
    "pdf": lambda b: b[:5] == b"%PDF-",
    "gz": lambda b: b[:3] == b"\x1f\x8b\x08",
    "sqlite": lambda b: b[:16] == b"SQLite format 3\x00",
    "wav": lambda b: b[:4] == b"RIFF" and b[8:12] == b"WAVE",
    "ttf": lambda b: b[:4] in (b"\x00\x01\x00\x00", b"true"),
}


def feats(b):
    a = np.frombuffer(b, dtype=np.uint8)
    n = len(a)
    hist = np.bincount(a, minlength=256).astype(np.float32)
    p = hist / n
    nz = p[p > 0]
    ent = float(-(nz * np.log2(nz)).sum())
    chi = float(((hist - n / 256) ** 2 / (n / 256)).sum() / n)
    zr = len(zlib.compress(b, 1)) / n
    ent2, dif, ac, run = 0.0, 0.0, 0.0, 1.0
    if n > 1:
        pair = a[:-1].astype(np.int32) * 256 + a[1:]
        c2 = np.bincount(pair, minlength=65536)
        q = c2[c2 > 0] / (n - 1)
        ent2 = float(-(q * np.log2(q)).sum()) / 16
        dif = float(np.abs(np.diff(a.astype(np.int16))).mean()) / 255
        if a.std() > 0:
            ac = float(np.corrcoef(a[:-1], a[1:])[0, 1])
        cut = np.flatnonzero(a[1:] != a[:-1])
        run = float(np.diff(np.concatenate(([0], cut + 1, [n]))).max()) / n
    ll = np.array([len(x) for x in b.split(b"\n")], dtype=np.float32)
    extra = [ent, p[0], p[255], p[32:127].sum(), p[128:].sum(), a.mean() / 255,
             a.std() / 255, (hist > 0).sum() / 256, zr, chi, ent2, dif, ac, run,
             len(ll) / 100.0, ll.mean() / 100.0, ll.std() / 100.0]
    return np.concatenate([p, np.array(extra, dtype=np.float32)])


def windows(data, k, r):
    n = len(data)
    if n <= WIN:
        return [data]
    return [data[o:o + WIN] for o in (r.randrange(0, n - WIN + 1) for _ in range(k))]


def check_content(cls, b):
    if cls in SIG:
        return SIG[cls](b)
    try:
        t = b[:2_000_000].decode("utf-8")
    except UnicodeDecodeError:
        return False
    s = t.lstrip()
    if len(s) < 100 or "\x00" in t:
        return False
    try:
        if cls == "json":
            return s[0] in "{[" and isinstance(json.loads(t), (dict, list))
        if cls == "xml":
            ET.fromstring(t)
            return s.startswith("<")
        if cls == "html":
            return "<html" in s[:2000].lower() or "<!doctype html" in s[:2000].lower()
    except Exception:
        return False
    return s[0] not in "<{["


class FragmentClassifier:
    def __init__(self, path=MODEL_PATH):
        d = joblib.load(path)
        self.model = d["model"]
        self.classes = d["classes"]

    def classify(self, data, k=8, seed=0):
        wins = windows(data, k, random.Random(seed))
        proba = self.model.predict_proba(np.array([feats(w) for w in wins])).mean(axis=0)
        i = int(proba.argmax())
        return self.classes[i], float(proba[i]), dict(zip(self.classes, proba.tolist()))