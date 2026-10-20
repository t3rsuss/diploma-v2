from pathlib import Path

import numpy as np

from src.parsing.parser import parse_binary

BLOCK = 4096


def block_entropies(arr: np.ndarray) -> np.ndarray:
    values = []
    for i in range(0, len(arr), BLOCK):
        blk = arr[i:i + BLOCK]
        if len(blk) < 256:
            continue
        counts = np.bincount(blk, minlength=256)
        p = counts[counts > 0] / len(blk)
        values.append(-(p * np.log2(p)).sum())
    return np.array(values) if values else np.zeros(1)


def extract(path) -> dict:
    path = Path(path)
    arr = np.frombuffer(path.read_bytes(), dtype=np.uint8)
    info = parse_binary(path)
    hist = np.bincount(arr, minlength=256) / max(len(arr), 1)
    be = block_entropies(arr)
    secs = info["sections"]

    row = {
        "file": info["file"],
        "format": info["format"],
        "size": len(arr),
        "file_entropy": info["file_entropy"],
        "blk_ent_mean": float(be.mean()),
        "blk_ent_std": float(be.std()),
        "blk_ent_min": float(be.min()),
        "blk_ent_max": float(be.max()),
        "frac_high_ent": float((be > 7.0).mean()),
        "zero_frac": float(hist[0]),
        "has_sections": int(len(secs) > 0),
        "n_sections": len(secs),
        "max_sec_entropy": max((s["entropy"] for s in secs), default=0.0),
        "n_imports": len(info["imports"]),
    }
    for i, v in enumerate(hist):
        row[f"h{i}"] = float(v)
    return row