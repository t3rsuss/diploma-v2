import sys
import json
import pathlib

import numpy as np
import joblib
import lightgbm as lgb
import pefile
import thrember

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.features.thrember_patch import apply

apply()

MODELS = ROOT / "src" / "models"
PRE = ROOT / "data" / "ember_models"
PRE_NAMES = {"elf": "ELF", "win64": "Win64", "dotnet": "Dot_Net",
             "win32": "Win32", "pe_generic": "PE"}
_CACHE = {}
_EXT = []


def _extractor():
    if not _EXT:
        _EXT.append(thrember.PEFeatureExtractor())
    return _EXT[0]


def file_kind(path):
    with open(path, "rb") as f:
        head = f.read(4)
    if head[:2] == b"MZ":
        return "PE"
    if head == b"\x7fELF":
        return "ELF"
    return None


def route(path):
    kind = file_kind(path)
    if kind is None:
        return None, None
    if kind == "ELF":
        return kind, "elf"
    try:
        pe = pefile.PE(str(path), fast_load=True)
        machine = pe.FILE_HEADER.Machine
        dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        dotnet = len(dirs) > 14 and dirs[14].VirtualAddress != 0
        pe.close()
    except Exception:
        return kind, "pe_generic"
    if dotnet:
        return kind, "dotnet"
    if machine == 0x8664:
        return kind, "win64"
    if machine == 0x14C:
        return kind, "win32"
    return kind, "pe_generic"


def _pre(name):
    key = "pre_" + name
    if key not in _CACHE:
        _CACHE[key] = lgb.Booster(model_file=str(PRE / f"EMBER2024_{name}.model"))
    return _CACHE[key]


def _own(key):
    if key not in _CACHE:
        metrics = {}
        mp = ROOT / "results" / f"detector_{key}_metrics.json"
        if mp.exists():
            metrics = json.loads(mp.read_text(encoding="utf-8"))
        _CACHE[key] = dict(
            booster=lgb.Booster(model_file=str(MODELS / f"detector_{key}.txt")),
            iso=joblib.load(MODELS / f"calibrator_{key}.joblib"),
            thr=json.loads((MODELS / f"thresholds_{key}.json").read_text(encoding="utf-8")),
            metrics=metrics,
        )
    return _CACHE[key]


def score_file(path):
    kind, key = route(path)
    if kind is None:
        return None
    with open(path, "rb") as f:
        data = f.read()
    vec = np.asarray(_extractor().feature_vector(data), dtype=np.float32).reshape(1, -1)
    pre = float(_pre(PRE_NAMES[key]).predict(vec)[0])
    out = dict(kind=kind, key=key, score_pre=pre)
    if key in ("elf", "win64"):
        m = _own(key)
        s = float(m["booster"].predict(vec)[0])
        out["score"] = s
        out["prob"] = float(m["iso"].predict([s])[0])
        out["t_mid"] = m["thr"]["thr_fpr_1"]
        out["t_high"] = m["thr"]["thr_fpr_01"]
        out["test_fpr_mid"] = m["metrics"].get("поріг FPR 1 %", {}).get("FPR на тесті")
        out["test_fpr_high"] = m["metrics"].get("поріг FPR 0,1 %", {}).get("FPR на тесті")
        out["source"] = "власна модель"
    else:
        out["score"] = pre
        out["t_mid"] = 0.2
        out["t_high"] = 0.5
        out["source"] = f"готова модель EMBER2024 ({PRE_NAMES[key]})"
    return out


def level(res):
    s = res["score"]
    if s >= res["t_high"]:
        return "high"
    if s >= res["t_mid"]:
        return "mid"
    return "low"