import pathlib
import random
import sys
from io import BytesIO

import numpy as np
from kaitaistruct import KaitaiStream

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import trace_lib as T

MAX_BYTES, PER_CLASS, SEED, MIN_COV, LOOKAHEAD, MIN_LEN, MAX_HEADER = 150_000, 30, 42, 0.98, 6, 4, 64
WANT = [a for a in sys.argv[1:] if a in T.FORMATS] or list(T.FORMATS)


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


files = T.collect_files()
rng = random.Random(SEED)
print(f"{'формат':7s}{'файлів':>7s}{'з зв.':>7s}{'зв./файл':>10s}{'джерело,%':>11s}{'ціль,%':>8s}{'обидва,%':>10s}"
      f"{'покр. наповн.,%':>17s}{'цілі в наповн.,%':>18s}", flush=True)
for c in WANT:
    mod, cls = T.FORMATS[c]
    Parser = T.load(mod, cls)
    lst = sorted(files[c])
    rng.shuffle(lst)
    n_ok = with_rel = rel_tot = src_ok = tgt_ok = both_ok = 0
    op_tot = op_hit = tm_tot = tm_in = 0
    for p in lst:
        if n_ok >= PER_CLASS:
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
            op, st = np.zeros(n, bool), np.zeros(n, bool)
            for s, e, o in rngs:
                s, e = max(0, s), min(n, e)
                if e > s:
                    (op if o else st)[s:e] = True
            st &= ~op
            if (op | st).mean() < MIN_COV:
                continue
            log = T.run_reader(c, data)
        except Exception:
            continue
        n_ok += 1
        E = set()
        for s, e, _ in rngs:
            E.add(s)
            E.add(e)
        rels = relations(log, data)
        tm = np.zeros(n, bool)
        for a, w, pj, v in rels:
            rel_tot += 1
            s_ok = a in E and a + w in E
            t_ok = pj in E and pj + v in E
            src_ok += s_ok
            tgt_ok += t_ok
            both_ok += s_ok and t_ok
            tm[pj:min(n, pj + v)] = True
        with_rel += bool(rels)
        op_tot += op.sum()
        op_hit += (tm & op).sum()
        tm_tot += tm.sum()
        tm_in += (tm & op).sum()
    if not n_ok:
        print(f"{c:7s}{0:7d}", flush=True)
        continue
    pct = lambda a, b: 100 * a / b if b else 0.0
    print(f"{c:7s}{n_ok:7d}{with_rel:7d}{rel_tot / n_ok:10.1f}{pct(src_ok, rel_tot):11.1f}{pct(tgt_ok, rel_tot):8.1f}"
          f"{pct(both_ok, rel_tot):10.1f}{pct(op_hit, op_tot):17.1f}{pct(tm_in, tm_tot):18.1f}", flush=True)
