import collections
import csv
import gzip
import importlib.util
import io
import pathlib
import sys
import wave
import zipfile

from kaitaistruct import KaitaiStruct
from PIL import Image

BASE = pathlib.Path(__file__).resolve().parents[1]
GEN = BASE / "kaitai_dbg"
sys.path.append(str(GEN))
sys.setrecursionlimit(10000)
BLOB, MAX_FIELDS = 64, 30_000
FORMATS = {
    "png": ("png", "Png"), "gif": ("gif", "Gif"), "ico": ("ico", "Ico"), "wav": ("wav", "Wav"),
    "gz": ("gzip", "Gzip"), "docx": ("zip", "Zip"),
}


class TraceIO(io.BytesIO):
    def __init__(self, data):
        super().__init__(data)
        self.log = []

    def _rec(self, pos, n):
        self.log.append((pos, n))
        if len(self.log) > 200_000:
            raise RuntimeError("надто багато читань")

    def read(self, size=-1):
        pos = self.tell()
        out = super().read(size)
        self._rec(pos, len(out))
        return out

    def read1(self, size=-1):
        return self.read(size)

    def readline(self, size=-1):
        pos = self.tell()
        out = super().readline(size)
        self._rec(pos, len(out))
        return out

    def readinto(self, b):
        pos = self.tell()
        n = super().readinto(b) or 0
        self._rec(pos, n)
        return n


def run_reader(fmt, data):
    f = TraceIO(data)
    if fmt in ("png", "gif", "ico"):
        im = Image.open(f)
        im.load()
    elif fmt == "wav":
        w = wave.open(f, "rb")
        w.readframes(w.getnframes())
    elif fmt == "gz":
        with gzip.GzipFile(fileobj=f) as g:
            while g.read(1 << 16):
                pass
    elif fmt == "docx":
        with zipfile.ZipFile(f) as z:
            for n in z.namelist():
                z.read(n)
    return [(p, l) for p, l in f.log if l > 0]


def load(modname, clsname):
    spec = importlib.util.spec_from_file_location("kd_" + modname, GEN / (modname + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return getattr(mod, clsname)


def touch(obj):
    for pname, attr in type(obj).__dict__.items():
        if isinstance(attr, property) and not pname.startswith("_"):
            try:
                getattr(obj, pname)
            except Exception:
                pass


def visit(val, parent, base, s, e, out, seen):
    if len(out) > MAX_FIELDS:
        raise RuntimeError("надто багато полів")
    if isinstance(val, KaitaiStruct):
        if id(val) in seen:
            return
        seen.add(id(val))
        child_base = base if val._io is parent._io else base + s
        before = len(out)
        walk(val, child_base, out, seen)
        if len(out) == before:
            out.append((base + s, base + e, False))
    else:
        out.append((base + s, base + e, (e - s) >= BLOB and isinstance(val, (bytes, bytearray, list))))


def walk(obj, base, out, seen):
    touch(obj)
    dbg = getattr(obj, "_debug", None)
    if not dbg:
        return
    for name, info in list(dbg.items()):
        try:
            val = getattr(obj, name)
        except Exception:
            continue
        s, e = info.get("start"), info.get("end")
        if "arr" in info and isinstance(val, list):
            if val and s is not None and e is not None and not any(isinstance(x, KaitaiStruct) for x in val):
                out.append((base + s, base + e, (e - s) >= BLOB))
                continue
            for item, ai in zip(val, info["arr"]):
                visit(item, obj, base, ai["start"], ai["end"], out, seen)
        elif s is not None and e is not None:
            visit(val, obj, base, s, e, out, seen)


def collect_files():
    files = collections.defaultdict(set)
    with open(BASE / "results" / "corpus_manifest_frozen.csv", encoding="utf-8", newline="") as fh:
        for r in csv.DictReader(fh):
            c = r["format"]
            if c in FORMATS:
                ext = r["ext"]
                p = BASE / "data" / "corpus" / c / (r["sha256"][:12] + ("." + ext if ext else ""))
                if p.exists():
                    files[c].add(p)
    for name in ("govdocs_dev.csv", "govdocs_test.csv"):
        with open(BASE / "results" / name, encoding="utf-8", newline="") as fh:
            for r in csv.DictReader(fh):
                if r["format"] in ("gif", "gz"):
                    files[r["format"]].add(pathlib.Path(r["src"]))
    return files
