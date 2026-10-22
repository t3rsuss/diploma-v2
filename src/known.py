import importlib.util
import pathlib
import sys
from io import BytesIO

from kaitaistruct import KaitaiStream, KaitaiStruct

GEN = pathlib.Path(__file__).resolve().parents[1] / "kaitai_dbg"
PARSERS = {
    "png": ("png", "Png"), "gif": ("gif", "Gif"), "ico": ("ico", "Ico"), "wav": ("wav", "Wav"),
    "gz": ("gzip", "Gzip"), "zip": ("zip", "Zip"), "docx": ("zip", "Zip"), "xlsx": ("zip", "Zip"),
    "pptx": ("zip", "Zip"), "ttf": ("ttf", "Ttf"), "sqlite": ("sqlite3", "Sqlite3"),
}
_cache = {}


def available(fmt):
    return fmt in PARSERS and GEN.exists()


def _parser(fmt):
    if fmt not in _cache:
        mod, cls = PARSERS[fmt]
        if str(GEN) not in sys.path:
            sys.path.append(str(GEN))
        spec = importlib.util.spec_from_file_location("kd_" + mod, GEN / (mod + ".py"))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        _cache[fmt] = getattr(m, cls)
    return _cache[fmt]


def _union(intervals, n):
    iv = sorted((max(0, s), min(n, e)) for s, e in intervals)
    total, cs, ce = 0, None, None
    for s, e in iv:
        if e <= s:
            continue
        if ce is None or s > ce:
            if ce is not None:
                total += ce - cs
            cs, ce = s, e
        else:
            ce = max(ce, e)
    return total + (ce - cs if ce is not None else 0)


def describe(data, fmt, limit=40):
    Parser = _parser(fmt)
    obj = Parser(KaitaiStream(BytesIO(data)))
    obj._read()
    for pname, attr in type(obj).__dict__.items():
        if isinstance(attr, property) and not pname.startswith("_"):
            try:
                getattr(obj, pname)
            except Exception:
                pass
    fields = []
    for name, info in getattr(obj, "_debug", {}).items():
        val = getattr(obj, name, None)
        if "arr" in info and isinstance(val, list):
            for i, (item, ai) in enumerate(zip(val, info["arr"])):
                fields.append((f"{name}[{i}]", ai["start"], ai["end"], type(item).__name__))
        elif info.get("start") is not None and info.get("end") is not None:
            fields.append((name, info["start"], info["end"], type(val).__name__))
    fields.sort(key=lambda f: f[1])
    cov = _union([(s, e) for _, s, e, _ in fields], len(data)) / max(len(data), 1)
    return {"parser": f"{Parser.__module__}.{Parser.__name__}", "fields_total": len(fields),
            "coverage_top_level": round(cov, 4),
            "fields": [dict(name=n, start=s, end=e, type=t) for n, s, e, t in fields[:limit]]}