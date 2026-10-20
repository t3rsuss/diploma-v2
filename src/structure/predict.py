import os
import pathlib
import joblib
import numpy as np

from src.structure.blocks import BLOCK, block_features, byte_labels

ROOT = pathlib.Path(__file__).resolve().parents[2]
MODEL_PATH = ROOT / "src" / "models" / "block_clf.joblib"
_model = None


def load_model():
    global _model
    if _model is None:
        _model = joblib.load(MODEL_PATH)["model"]
    return _model


def predict_blocks(path, max_bytes=20_000_000):
    data = np.fromfile(str(path), dtype=np.uint8, count=max_bytes)
    n = len(data) // BLOCK
    if n < 2:
        return None
    blocks = data[: n * BLOCK].reshape(n, BLOCK)
    f = block_features(blocks)
    idx = np.arange(n)
    prev = f[np.clip(idx - 1, 0, n - 1)]
    nxt = f[np.clip(idx + 1, 0, n - 1)]
    rel = (idx / max(n - 1, 1)).astype(np.float32)[:, None]
    X = np.hstack([f, prev, nxt, rel])
    pred = load_model().predict(X).astype(int)
    return pred, f[:, 64], n


def table_labels(path, n):
    res = byte_labels(path, n * BLOCK)
    if res is None:
        return None, None
    fmt, lab = res
    return fmt, lab[: n * BLOCK].reshape(n, BLOCK)[:, 0].astype(int)