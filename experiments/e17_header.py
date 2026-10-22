import pathlib
import random
import sys
from io import BytesIO

import numpy as np
from kaitaistruct import KaitaiStream

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import trace_lib as T

H, CONST, MAX_BYTES, PER_CLASS, SEED, MIN_COV = 64, 0.9, 150_000, 30, 42, 0.98
LOOKAHEAD, MIN_LEN, MAX_HEADER = 6, 4, 64
WANT = [a for a in sys.argv[1:] if a in T.FORMATS] or list(T.FORMATS)
VARIANTS = ["кожні 4 байти", "читання", "читання+довжини", "константи", "усе разом"]


def relations(log, data):
    n = len(data)
    best = {}
    for i, (pos, ln) in enumerate(log):
        if ln > MAX_HEADER:
            continue
        for k in range(ln):
            for w in (1, 2, 4):
                if k + w > ln:
                    continue
                raw = data[pos + k:pos + k + w]
                for order in ("little", "big"):
                    if w == 1 and order == "big":
                        continue
                    v = int.from_bytes(raw, order)
                    if v < MIN_LEN or v > n:
                        continue
                    for j in range(i + 1, min(i + 1 + LOOKAHEAD, len(log))):
                        pj, lj = log[j]
                        if lj == v and pj >= pos + ln:
                            cand = (w, -(pos + k), pos + k, v)
                            if pj not in best or cand > best[pj]:
                                best[pj] = cand
                            break
    return [(a, w, pj, v) for pj, (w, _, a, v) in best.items()]


def inside(edges):
    return {e for e in edges if 0 < e < H}


def prf(tp, npred, nt):
    p = tp / npred if npred else 0.0
    r = tp / nt if nt else 0.0
    return p, r, (2 * p * r / (p + r) if p + r else 0.0)


files = T.collect_files()
rng = random.Random(SEED)
print(f"{'формат':7s}{'файлів':>7s}{'варіант':>20s}{'P':>7s}{'R':>7s}{'F1':>7s}", flush=True)
for c in WANT:
    mod, cls = T.FORMATS[c]
    Parser = T.load(mod, cls)
    lst = sorted(files[c])
    rng.shuffle(lst)
    items = []
    for p in lst:
        if len(items) >= PER_CLASS:
            break
        try:
            if not (1024 <= p.stat().st_size <= MAX_BYTES):
                continue
            data = p.read_bytes()
            print(f"  {c}: {p.name}", file=sys.stderr, flush=True)
            obj = Parser(KaitaiStream(BytesIO(data)))
            obj._read()
            rngs = []
            T.walk(obj, 0, rngs, {id(obj)})
            n = len(data)
            cov = np.zeros(n, bool)
            for s, e, _ in rngs:
                cov[max(0, s):min(n, e)] = True
            if cov.mean() < MIN_COV or n < H:
                continue
            log = T.run_reader(c, data)
            E = set()
            for s, e, _ in rngs:
                E.add(s)
                E.add(e)
            items.append(dict(data=data, log=log, E=E, rels=relations(log, data)))
        except Exception:
            continue
    if len(items) < 6:
        print(f"{c:7s}{len(items):7d}  замало файлів", flush=True)
        continue
    half = len(items) // 2
    A, B = items[:half], items[half:]
    M = np.zeros((H, 256))
    for it in A:
        for i, b in enumerate(it["data"][:H]):
            M[i, b] += 1
    const = (M.max(1) / len(A)) >= CONST
    edges_c = {i + 1 for i in range(H - 1) if const[i] != const[i + 1]}
    counts = {v: [0, 0, 0] for v in VARIANTS}
    for it in B:
        truth = inside(it["E"])
        ra = inside({e for p, l in it["log"] for e in (p, p + l)})
        rl = inside({e for a, w, pj, v in it["rels"] for e in (a, a + w, pj, pj + v)})
        preds = {
            "кожні 4 байти": set(range(4, H, 4)),
            "читання": ra,
            "читання+довжини": ra | rl,
            "константи": set(edges_c),
            "усе разом": ra | rl | edges_c,
        }
        for v in VARIANTS:
            tp = len(preds[v] & truth)
            counts[v][0] += tp
            counts[v][1] += len(preds[v])
            counts[v][2] += len(truth)
    for v in VARIANTS:
        p_, r_, f_ = prf(*counts[v])
        print(f"{c:7s}{len(B):7d}{v:>20s}{p_:7.2f}{r_:7.2f}{f_:7.2f}", flush=True)
