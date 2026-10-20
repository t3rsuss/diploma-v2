from pathlib import Path

import lief
import numpy as np

try:
    lief.logging.disable()
except Exception:
    pass


def byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(data)
    return float(-(p * np.log2(p)).sum())


def parse_binary(path) -> dict:
    path = Path(path)
    data = path.read_bytes()
    info = {
        "file": path.name,
        "size": len(data),
        "file_entropy": round(byte_entropy(data), 3),
        "format": None,
        "entrypoint": None,
        "sections": [],
        "imports": [],
        "error": None,
    }
    try:
        binary = lief.parse(str(path))
    except Exception as exc:
        info["error"] = str(exc)
        return info
    if binary is None:
        info["error"] = "lief: не вдалося розібрати"
        return info

    if isinstance(binary, lief.PE.Binary):
        info["format"] = "PE"
    elif isinstance(binary, lief.ELF.Binary):
        info["format"] = "ELF"
    else:
        info["format"] = "other"

    info["entrypoint"] = int(binary.entrypoint)
    info["sections"] = [
        {"name": s.name, "size": int(s.size), "entropy": float(s.entropy)}
        for s in binary.sections
    ]
    try:
        info["imports"] = [f.name for f in binary.imported_functions]
    except Exception:
        info["imports"] = []
    return info