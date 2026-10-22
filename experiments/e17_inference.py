import collections
import pathlib
import random
import struct
import sys
import zlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from trace_lib import TraceIO

HDR_ZONE, MAX_HEADER, LOOKAHEAD, MIN_LEN, CONST_FRAC = 64, 64, 6, 4, 0.8
SEED, N_FILES = 42, 40


def make_xdat(rng):
    n = rng.randint(3, 9)
    body = b"XDT1" + struct.pack("<HHI", 1, n, rng.getrandbits(32))
    for _ in range(n):
        tag = rng.choice([1, 2, 3, 7])
        ln = rng.randint(8, 300)
        body += struct.pack("<BH", tag, ln) + bytes(rng.getrandbits(8) for _ in range(ln))
    return body + struct.pack("<I", zlib.crc32(body))


def truth_xdat(data):
    n = struct.unpack("<H", data[6:8])[0]
    f = [(0, 4, "константа"), (4, 6, "константа"), (6, 8, "лічильник"), (8, 12, "змінне поле")]
    pos = 12
    for _ in range(n):
        ln = struct.unpack("<H", data[pos + 1:pos + 3])[0]
        f += [(pos, pos + 1, "тип запису"), (pos + 1, pos + 3, "довжина"), (pos + 3, pos + 3 + ln, "дані (блок)")]
        pos += 3 + ln
    f.append((pos, pos + 4, "CRC-32"))
    return f


def read_xdat(fp):
    magic, ver, n, flags = struct.unpack("<4sHHI", fp.read(12))
    assert magic == b"XDT1"
    for _ in range(n):
        tag = fp.read(1)[0]
        ln = struct.unpack("<H", fp.read(2))[0]
        fp.read(ln)
    fp.read(4)


def trace(data, reader):
    f = TraceIO(data)
    reader(f)
    return [(p, l) for p, l in f.log if l > 0]


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
                            cand = (w, (pos + k) % w == 0, -(pos + k), pos + k, v)
                            if pj not in best or cand > best[pj]:
                                best[pj] = cand
                            break
    return [(a, w, pj, v) for pj, (w, _, _, a, v) in best.items()]


def crc_ok(data, pos, ln, starts):
    if ln != 4:
        return False
    raw = data[pos:pos + 4]
    vals = {int.from_bytes(raw, "little"), int.from_bytes(raw, "big")}
    for a in starts:
        if a < pos and zlib.crc32(data[a:pos]) in vals:
            return True
    return False


def prune(uniq):
    res = []
    for p, l in uniq:
        inner = sorted((q, m) for q, m in uniq if (q, m) != (p, l) and q >= p and q + m <= p + l)
        pos, ok = p, bool(inner)
        for q, m in inner:
            if q > pos:
                ok = False
                break
            pos = max(pos, q + m)
        if ok and pos >= p + l:
            continue
        res.append((p, l))
    return res


def infer(samples):
    """samples: список (data, log). Повертає для кожного зразка список (початок, кінець, роль)."""
    nfiles = len(samples)
    hdr_const = []
    for o in range(HDR_ZONE):
        vals = {d[o] for d, _ in samples if len(d) > o}
        hdr_const.append(len(vals) == 1)
    key_freq, small_vals, cnt_votes = {}, {}, {}
    prepared = []
    for d, log in samples:
        uniq = prune(sorted(set(log)))
        rels = relations(log, d)
        prepared.append((d, uniq, rels))
        for key in {(l, d[p:p + l]) for p, l in uniq if l <= 16}:
            key_freq[key] = key_freq.get(key, 0) + 1
        for p, l in uniq:
            if l in (1, 2):
                small_vals.setdefault(l, set()).add(d[p:p + l])
        n_rel = len(rels)
        if n_rel >= 2:
            seen_k = set()
            for p, l in uniq:
                if l >= 8 and p + l <= HDR_ZONE:
                    for k in range(p, p + l):
                        for w in (1, 2, 4):
                            if k + w <= p + l:
                                for order in ("little", "big"):
                                    if int.from_bytes(d[k:k + w], order) == n_rel:
                                        seen_k.add((k, w))
            for key in seen_k:
                cnt_votes[key] = cnt_votes.get(key, 0) + 1
    good = [(w, k % w == 0, -k, k) for (k, w), c in cnt_votes.items() if c >= 0.9 * nfiles]
    cf = None
    if good:
        w, _, _, k = max(good)
        cf = (k, k + w)
    out = []
    for d, uniq, rels in prepared:
        src = {(a, a + w) for a, w, _, _ in rels}
        tgt = {(pj, pj + v) for _, _, pj, v in rels}
        reps = {}
        for p, l in uniq:
            reps[l] = reps.get(l, 0) + 1
        starts = [0] + [x for p, _ in uniq for x in (p, p + 4)]
        fields = []
        for p, l in uniq:
            cuts = {p, p + l}
            inside = [(a, b) for a, b in src if p <= a and b <= p + l and l <= MAX_HEADER]
            for a, b in inside:
                cuts.update((a, b))
            in_hdr = l >= 8 and p + l <= HDR_ZONE
            if in_hdr:
                for o in range(p + 1, p + l):
                    if hdr_const[o] != hdr_const[o - 1]:
                        cuts.add(o)
                if cf and p <= cf[0] and cf[1] <= p + l:
                    inside.append(cf)
                    cuts.update(cf)
            for a, b in inside:
                cuts = {c for c in cuts if not (a < c < b)}
            cs = sorted(cuts)
            for a, b in zip(cs, cs[1:]):
                if (a, b) in src:
                    fields.append((a, b, "довжина"))
                elif cf and (a, b) == cf and in_hdr:
                    fields.append((a, b, "лічильник"))
                elif in_hdr:
                    fields.append((a, b, "константа" if all(hdr_const[a:b]) else "змінне поле"))
                else:
                    fields.append((a, b, None))
        res = []
        for a, b, role in fields:
            l = b - a
            if role is None:
                if (a, b) in tgt or l > MAX_HEADER:
                    role = "дані (блок)"
                elif crc_ok(d, a, l, starts):
                    role = "CRC-32"
                elif l in (1, 2) and reps.get(l, 0) >= 3 and len(small_vals.get(l, ())) <= 8:
                    role = "тип запису"
                elif l <= 16 and key_freq.get((l, d[a:b]), 0) >= CONST_FRAC * nfiles:
                    role = "константа"
                else:
                    role = "змінне поле"
            res.append((a, b, role))
        out.append(res)
    return out


def score(pred, truth):
    pe = {x for a, b, _ in pred for x in (a, b)}
    te = {x for a, b, _ in truth for x in (a, b)}
    tp = len(pe & te)
    exact = {(a, b): r for a, b, r in truth}
    matched = [(a, b, r) for a, b, r in pred if (a, b) in exact]
    ok = sum(1 for a, b, r in matched if exact[(a, b)] == r)
    return tp, len(pe), len(te), ok, len(matched), len(exact)


def describe(fields, d, limit=18):
    for a, b, r in fields[:limit]:
        print(f"  {a:6d}..{b:<6d} {b - a:6d} Б  {r:14s} {d[a:min(b, a + 8)].hex()}")


def synthetic():
    rng = random.Random(SEED)
    datas = [make_xdat(rng) for _ in range(N_FILES)]
    samples = [(d, trace(d, read_xdat)) for d in datas]
    inferred = infer(samples)
    tp = npred = nt = ok = nm = nex = 0
    conf = collections.Counter()
    for (d, _), pred in zip(samples, inferred):
        a = score(pred, truth_xdat(d))
        tp, npred, nt, ok, nm, nex = (x + y for x, y in zip((tp, npred, nt, ok, nm, nex), a))
        ex = {(s, e): r for s, e, r in truth_xdat(d)}
        for s, e, r in pred:
            if (s, e) in ex and ex[(s, e)] != r:
                conf[(ex[(s, e)], r)] += 1
    print(f"Синтетичний формат XDT1, {N_FILES} файлів, програма-читач на Python")
    print(f"  межі полів: точність {100 * tp / npred:.1f} %, повнота {100 * tp / nt:.1f} %")
    print(f"  ролі: {100 * ok / nm:.1f} % серед збіжних полів, {100 * ok / nex:.1f} % серед усіх істинних полів")
    print("  помилки ролей (істинна -> знайдена):", dict(conf))
    print("Відновлений опис першого файла:")
    describe(inferred[0], samples[0][0])


def real(fmts):
    import trace_lib as T
    from kaitaistruct import KaitaiStream
    from io import BytesIO
    files = T.collect_files()
    rng = random.Random(SEED)
    for c in fmts:
        if c not in T.FORMATS:
            continue
        mod, cls = T.FORMATS[c]
        Parser = T.load(mod, cls)
        lst = sorted(files[c])
        rng.shuffle(lst)
        samples, edge_sets = [], []
        for p in lst:
            if len(samples) >= N_REAL:
                break
            try:
                if not (1024 <= p.stat().st_size <= 150_000):
                    continue
                data = p.read_bytes()
                log = T.run_reader(c, data)
                if len(log) > 3000:
                    continue
                obj = Parser(KaitaiStream(BytesIO(data)))
                obj._read()
                rngs = []
                T.walk(obj, 0, rngs, {id(obj)})
            except Exception:
                continue
            E = set()
            for s, e, _ in rngs:
                E.add(s)
                E.add(e)
            samples.append((data, log))
            edge_sets.append(E)
        if len(samples) < 5:
            print(f"{c}: замало файлів ({len(samples)})")
            continue
        inferred = infer(samples)
        hit = npred = ntrue = 0
        roles = collections.Counter()
        for pred, E in zip(inferred, edge_sets):
            pe = {x for a, b, _ in pred for x in (a, b)}
            hit += len(pe & E)
            npred += len(pe)
            ntrue += len(E)
            for a, b, r in pred:
                roles[r] += b - a
        tot = sum(roles.values())
        print(f"\n{c}: файлів {len(samples)}, межі: точність {100 * hit / npred:.1f} %, "
              f"частка меж еталона Kaitai, що знайдені: {100 * hit / ntrue:.1f} %")
        print("  частка байтів за ролями:", {r: f"{100 * v / tot:.1f} %" for r, v in roles.most_common()})
        print("  відновлений опис першого файла:")
        describe(inferred[0], samples[0][0])


N_REAL = 30
if __name__ == "__main__":
    args = sys.argv[1:]
    if not args or "synthetic" in args:
        synthetic()
    fm = [a for a in args if a != "synthetic"] or (["png", "docx"] if not args else [])
    if fm:
        real(fm)
