"""Версія 2 відновлення полів: контекст читання (точка коду) + правила довжин, перевірені по файлах."""
import collections
import zlib

MAX_HEADER, HDR_ZONE, LOOK = 64, 64, 40
MIN_VAL = 1
RULE_MIN_OCC, RULE_MIN_SUPPORT, RULE_MIN_DISTINCT = 5, 0.6, 3
CONST_FRAC, TYPE_MAX_VALUES = 0.8, 16
SINGLES = 8


def candidates(ln):
    for k in range(ln):
        for w in (1, 2, 4):
            if k + w <= ln:
                for order in (("little",) if w == 1 else ("little", "big")):
                    yield k, w, order


def uleb(data, start, stop):
    # Декодує змінну довжину (LEB128): 7 біт на байт, старший біт - ознака продовження.
    value, shift = 0, 0
    for i in range(start, stop):
        b = data[i]
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, i - start + 1
        shift += 7
        if shift > 28:
            break
    return None, 0


def read_value(data, pos, k, w, order):
    if order == "uleb":
        return uleb(data, pos + k, pos + k + w)[0]
    return int.from_bytes(data[pos + k:pos + k + w], order)


def read_candidates(data, pos, ln):
    for k, w, order in candidates(ln):
        yield k, w, order, int.from_bytes(data[pos + k:pos + k + w], order)
    for k in range(ln):
        v, w = uleb(data, pos + k, pos + ln)
        if v is not None and w >= 2:
            yield k, w, "uleb", v


def merge_runs(samples):
    # Склеює суміжні однобайтні читання з одного місця коду, якщо довжина такої серії змінна.
    run_lengths = collections.defaultdict(set)
    all_runs = []
    for data, log in samples:
        runs, i = [], 0
        while i < len(log):
            ctx = log[i][2]
            j = i
            if log[i][1] == 1:
                while (j + 1 < len(log) and log[j + 1][1] == 1 and log[j + 1][2] == ctx
                       and log[j + 1][0] == log[j][0] + 1):
                    j += 1
                run_lengths[ctx].add(j - i + 1)
            runs.append((i, j))
            i = j + 1
        all_runs.append(runs)
    variable = {ctx for ctx, lens in run_lengths.items() if len(lens) > 1}
    out = []
    for (data, log), runs in zip(samples, all_runs):
        merged = []
        for i, j in runs:
            pos, ln, ctx = log[i]
            if ln == 1 and ctx in variable:
                merged.append((pos, j - i + 1, ctx))
            else:
                merged.extend(log[i:j + 1])
        out.append((data, merged))
    return out


def following(log, i, end):
    # Читання після i: початок ланцюжка, префіксні суми ланцюжка та окремі довжини найближчих читань.
    start, total, prev, sums, singles = None, 0, None, [], []
    chain = True
    for p, l, _ in log[i + 1:i + 1 + LOOK]:
        if p < end:
            continue
        if len(singles) < SINGLES:
            singles.append((p, l))
        if chain:
            if prev is not None and p != prev:
                chain = False
            else:
                if start is None:
                    start = p
                total += l
                prev = p + l
                sums.append(total)
        if not chain and len(singles) >= SINGLES:
            break
    return start, sums, singles


def learn_rules_v2(samples):
    stat = collections.defaultdict(lambda: [0, 0])
    vals = collections.defaultdict(set)
    for data, log in samples:
        for i, (pos, ln, ctx) in enumerate(log):
            if ln > MAX_HEADER:
                continue
            _, sums, singles = following(log, i, pos + ln)
            sumset = set(sums) | {l for _, l in singles}
            for k, w, order, v in read_candidates(data, pos, ln):
                key = (ctx, ln, k, w, order)
                stat[key][0] += 1
                if v >= MIN_VAL and v in sumset:
                    stat[key][1] += 1
                    if len(vals[key]) < RULE_MIN_DISTINCT:
                        vals[key].add(v)
    good = []
    for key, (occ, hit) in stat.items():
        if occ >= RULE_MIN_OCC and hit / occ >= RULE_MIN_SUPPORT and len(vals[key]) >= RULE_MIN_DISTINCT:
            good.append((key, hit / occ))
    good.sort(key=lambda kv: (-round(kv[1], 3), kv[0][2] % kv[0][3] != 0, -kv[0][3], kv[0][4] != "little", kv[0][2]))
    chosen = {}
    for (ctx, ln, k, w, order), sup in good:
        taken = chosen.setdefault((ctx, ln), [])
        if any(k < k2 + w2 and k2 < k + w for k2, w2, _, _ in taken):
            continue
        taken.append((k, w, order, sup))
    return widen(chosen, samples)


def widen(chosen, samples):
    # Розширює поле довжини, якщо сусідні байти в усіх випадках нульові й не належать іншому правилу.
    occ = collections.defaultdict(list)
    for data, log in samples:
        for pos, ln, ctx in log:
            if (ctx, ln) in chosen:
                occ[(ctx, ln)].append((data, pos))
    for site, rules in chosen.items():
        for idx in range(len(rules)):
            k, w, order, sup = rules[idx]
            if order == "uleb":
                continue
            for w2 in (2, 4):
                if w2 <= w:
                    continue
                ext = range(k + w, k + w2) if order == "little" else range(k - (w2 - w), k)
                lo, hi = min(ext), max(ext) + 1
                if lo < 0 or hi > site[1]:
                    continue
                if any(k3 < hi and lo < k3 + w3 for j, (k3, w3, _, _) in enumerate(rules) if j != idx):
                    continue
                if all(not any(d[pos + o] for o in ext) for d, pos in occ[site]):
                    k, w = min(k, lo), w2
                    rules[idx] = (k, w, order, sup)
    return chosen


def crc_ok(data, pos, ln, starts):
    if ln != 4:
        return False
    raw = data[pos:pos + 4]
    values = {int.from_bytes(raw, "little"), int.from_bytes(raw, "big")}
    return any(a < pos and zlib.crc32(data[a:pos]) in values for a in starts)


def prune(reads):
    keys = sorted({(p, l) for p, l, _ in reads})
    drop = set()
    for p, l in keys:
        inner = sorted((q, m) for q, m in keys if (q, m) != (p, l) and q >= p and q + m <= p + l)
        pos, ok = p, bool(inner)
        for q, m in inner:
            if q > pos:
                ok = False
                break
            pos = max(pos, q + m)
        if ok and pos >= p + l:
            drop.add((p, l))
    seen, out = set(), []
    for p, l, c in sorted(reads):
        if (p, l) not in drop and (p, l) not in seen:
            seen.add((p, l))
            out.append((p, l, c))
    return out



MAX_MARKERS = 2
MARKER_REST_HIT = 0.9
MARKER_VALUES = {}


def learn_rules(samples):
    chosen = learn_rules_v2(samples)
    MARKER_VALUES.clear()
    cells = collections.defaultdict(dict)

    for data, log in samples:
        for i, (pos, ln, ctx) in enumerate(log):
            if ln > MAX_HEADER:
                continue
            _, sums, singles = following(log, i, pos + ln)
            targets = set(sums) | {size for _, size in singles}
            for k, w, order, value in read_candidates(data, pos, ln):
                key = (ctx, ln, k, w, order)
                count = cells[key].setdefault(value, [0, 0])
                count[0] += 1
                count[1] += int(value >= MIN_VAL and value in targets)

    good = []
    for key, counts in cells.items():
        markers = frozenset(
            value for value, (_, hits) in counts.items() if hits == 0
        )
        if not 1 <= len(markers) <= MAX_MARKERS:
            continue
        remaining = [
            count for value, count in counts.items() if value not in markers
        ]
        occurrences = sum(count for count, _ in remaining)
        if occurrences < RULE_MIN_OCC or len(remaining) < RULE_MIN_DISTINCT:
            continue
        if any(hits / count < MARKER_REST_HIT for count, hits in remaining):
            continue
        support = sum(hits for _, hits in remaining) / occurrences
        if support < RULE_MIN_SUPPORT:
            continue
        good.append((key, support, markers))

    good.sort(key=lambda item: (
        -round(item[1], 3),
        item[0][2] % item[0][3] != 0,
        -item[0][3],
        item[0][4] != "little",
        item[0][2],
    ))

    for (ctx, ln, k, w, order), support, markers in good:
        rules = chosen.setdefault((ctx, ln), [])
        if any(k < k2 + w2 and k2 < k + w for k2, w2, _, _ in rules):
            continue
        rules.append((k, w, order, support))
        MARKER_VALUES[(ctx, ln, k, w, order)] = markers

    return chosen


def infer2(samples):
    samples = merge_runs(samples)
    nfiles = len(samples)
    rules = learn_rules(samples)

    hdr_const = []
    for o in range(HDR_ZONE):
        vs = {d[o] for d, _ in samples if len(d) > o}
        hdr_const.append(len(vs) == 1)

    prepared = []
    key_freq, site_occ = {}, collections.Counter()
    site_vals = collections.defaultdict(set)
    cnt_votes = {}
    for data, log in samples:
        src, tgt = [], []
        for i, (pos, ln, ctx) in enumerate(log):
            for k, w, order, _ in rules.get((ctx, ln), ()):
                v = read_value(data, pos, k, w, order)
                if v is None:
                    continue
                if v in MARKER_VALUES.get((ctx, ln, k, w, order), ()):
                    continue
                src.append((pos + k, pos + k + w))
                start, sums, singles = following(log, i, pos + ln)
                if v >= MIN_VAL and v in sums:
                    tgt.append((start, start + v))
                elif v >= MIN_VAL:
                    for p2, l2 in singles:
                        if l2 == v:
                            tgt.append((p2, p2 + v))
                            break
        reads = prune(log)
        prepared.append((data, reads, set(src), tgt))

        for key in {(l, data[p:p + l]) for p, l, _ in reads if l <= 16}:
            key_freq[key] = key_freq.get(key, 0) + 1
        for p, l, c in reads:
            if l <= 4:
                site_occ[(c, l)] += 1
                if len(site_vals[(c, l)]) <= TYPE_MAX_VALUES:
                    site_vals[(c, l)].add(data[p:p + l])
        n_rel = len(src)
        if n_rel >= 2:
            seen_k = set()
            for p, l, _ in reads:
                if l >= 8 and p + l <= HDR_ZONE:
                    for k in range(p, p + l):
                        for w in (1, 2, 4):
                            if k + w <= p + l:
                                for order in ("little", "big"):
                                    if int.from_bytes(data[k:k + w], order) == n_rel:
                                        seen_k.add((k, w))
            for key in seen_k:
                cnt_votes[key] = cnt_votes.get(key, 0) + 1

    good = [(w, k % w == 0, -k, k) for (k, w), c in cnt_votes.items() if c >= 0.9 * nfiles]
    cf = None
    if good:
        w, _, _, k = max(good)
        cf = (k, k + w)

    site_files = collections.Counter()
    for data, reads, _, _ in prepared:
        for site in {(c, l) for _, l, c in reads if l <= 4}:
            site_files[site] += 1

    out = []
    for data, reads, src, tgt in prepared:
        starts = [0] + [x for p, _, _ in reads for x in (p, p + 4)]
        fields = []
        for p, l, ctx in reads:
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
                whole = (a == p and b == p + l)
                in_tgt = any(ts <= a and b <= te for ts, te in tgt)
                if (a, b) in src:
                    fields.append((a, b, "довжина", ctx, whole))
                elif cf and (a, b) == cf and in_hdr:
                    fields.append((a, b, "лічильник", ctx, whole))
                elif in_hdr and whole and in_tgt and not any(hdr_const[a:b]):
                    fields.append((a, b, None, ctx, whole))
                elif in_hdr:
                    fields.append((a, b, "константа" if all(hdr_const[a:b]) else "змінне поле", ctx, whole))
                else:
                    fields.append((a, b, None, ctx, whole))
        res = []
        for a, b, role, ctx, whole in fields:
            l = b - a
            if role is None:
                site = (ctx, l)
                if any(ts <= a and b <= te for ts, te in tgt) or l > MAX_HEADER:
                    role = "дані (блок)"
                elif crc_ok(data, a, l, starts):
                    role = "CRC-32"
                elif (whole and l <= 4 and site_files.get(site, 0) and site_occ[site] / site_files[site] >= 2
                      and 2 <= len(site_vals[site]) <= TYPE_MAX_VALUES):
                    role = "тип запису"
                elif l <= 16 and key_freq.get((l, data[a:b]), 0) >= CONST_FRAC * nfiles:
                    role = "константа"
                else:
                    role = "змінне поле"
            res.append((a, b, role))
        out.append(res)
    return out
