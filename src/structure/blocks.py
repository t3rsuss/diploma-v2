import warnings
import numpy as np
import lief

warnings.filterwarnings("ignore", category=RuntimeWarning)
try:
    lief.logging.disable()
except Exception:
    pass

BLOCK = 512
PER_CLASS = 60
CLASSES = ["header", "code", "rodata", "data", "resources", "other"]
HEADER, CODE, RODATA, DATA, RES, OTHER = range(6)

_BASE = [f"h{i}" for i in range(64)] + [
    "entropy", "zeros", "ff", "printable", "high", "mean", "std", "uniq"
]
FEATURE_NAMES = (_BASE + [f"prev_{x}" for x in _BASE]
                 + [f"next_{x}" for x in _BASE] + ["rel_pos"])


def _enum_int(v):
    return int(getattr(v, "value", v))


def _pe_class(s):
    name = s.name.lower()
    ch = int(s.characteristics)
    if name == ".rsrc":
        return RES
    if name in (".reloc", ".debug"):
        return OTHER
    if ch & 0x20000000 or ch & 0x20:
        return CODE
    if ch & 0x80000000:
        return DATA
    return RODATA


def _elf_class(s):
    fl = int(s.flags)
    if fl & 4:
        return CODE
    if not fl & 2:
        return OTHER
    if fl & 1:
        return DATA
    return RODATA


def byte_labels(path, size):
    binary = lief.parse(str(path))
    if binary is None:
        return None
    if isinstance(binary, lief.PE.Binary):
        fmt, cls_fn = "PE", _pe_class
    elif isinstance(binary, lief.ELF.Binary):
        fmt, cls_fn = "ELF", _elf_class
    else:
        return None

    lab = np.full(size, OTHER, dtype=np.uint8)
    spans = []
    for s in binary.sections:
        off, sz = int(s.offset), int(s.size)
        if fmt == "ELF" and _enum_int(s.type) == 8:
            continue
        if sz <= 0 or off <= 0 or off >= size:
            continue
        spans.append((off, min(off + sz, size), cls_fn(s)))
    if not spans:
        return None
    first = min(a for a, _, _ in spans)
    lab[:first] = HEADER
    for a, b, c in spans:
        lab[a:b] = c
    return fmt, lab


def block_features(blocks):
    n = len(blocks)
    hist = np.zeros((n, 256), dtype=np.float32)
    for i in range(n):
        hist[i] = np.bincount(blocks[i], minlength=256)
    p = hist / BLOCK
    logp = np.zeros_like(p)
    np.log2(p, out=logp, where=p > 0)
    ent = -(p * logp).sum(1)
    h64 = p.reshape(n, 64, 4).sum(2)
    extra = np.stack([
        ent,
        p[:, 0],
        p[:, 255],
        p[:, 32:127].sum(1),
        p[:, 128:].sum(1),
        blocks.mean(1) / 255.0,
        blocks.std(1) / 255.0,
        (hist > 0).sum(1) / 256.0,
    ], axis=1)
    return np.hstack([h64, extra]).astype(np.float32)


def file_blocks(path, rng=None):
    rng = rng or np.random.default_rng(42)
    data = np.fromfile(str(path), dtype=np.uint8)
    n = len(data) // BLOCK
    if n < 2:
        return None
    res = byte_labels(path, len(data))
    if res is None:
        return None
    fmt, lab = res
    blocks = data[: n * BLOCK].reshape(n, BLOCK)
    lab_b = lab[: n * BLOCK].reshape(n, BLOCK)
    uniform = (lab_b == lab_b[:, :1]).all(axis=1)
    cls = lab_b[:, 0]

    keep = []
    for c in range(len(CLASSES)):
        idx = np.where(uniform & (cls == c))[0]
        if len(idx) > PER_CLASS:
            idx = rng.choice(idx, PER_CLASS, replace=False)
        keep.extend(idx.tolist())
    if not keep:
        return None
    keep = np.array(sorted(keep))

    prev = np.clip(keep - 1, 0, n - 1)
    nxt = np.clip(keep + 1, 0, n - 1)
    need = np.unique(np.concatenate([keep, prev, nxt]))
    f = block_features(blocks[need])
    ic, ip, inx = (np.searchsorted(need, a) for a in (keep, prev, nxt))
    rel = (keep / max(n - 1, 1)).astype(np.float32)[:, None]
    X = np.hstack([f[ic], f[ip], f[inx], rel])
    return fmt, X, cls[keep].astype(np.int64)