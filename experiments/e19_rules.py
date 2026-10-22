import collections
import pathlib
import random
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import e18_context as CTX

MAX_HDR, MIN_LEN, LOOK = 64, 4, 6
LEARN_MIN_SUPPORT, LEARN_MIN_OCC, PASS_ACC, PART_ACC = 0.6, 5, 0.95, 0.6
PER_CLASS, SEED, MAX_BYTES = 40, 42, 150_000


def targets(log, i, end):
    sums, tot, prev = set(), 0, None
    for p, l, _ in log[i + 1:i + 1 + LOOK]:
        if p < end:
            continue
        if prev is not None and p != prev:
            break
        tot += l
        prev = p + l
        sums.add(tot)
    return sums


def candidates(ln):
    for k in range(ln):
        for w in (1, 2, 4):
            if k + w <= ln:
                for order in (("little",) if w == 1 else ("little", "big")):
                    yield k, w, order


def learn(logs, datas):
    S = collections.defaultdict(lambda: [0, 0])
    V = collections.defaultdict(set)
    for log, data in zip(logs, datas):
        for i, (pos, ln, ctx) in enumerate(log):
            if ln > MAX_HDR:
                continue
            sums = targets(log, i, pos + ln)
            for k, w, order in candidates(ln):
                v = int.from_bytes(data[pos + k:pos + k + w], order)
                key = (ctx, ln, k, w, order)
                S[key][0] += 1
                if v >= MIN_LEN and v in sums:
                    S[key][1] += 1
                if len(V[key]) < 4:
                    V[key].add(v)
    return S, V


def evaluate_rule(logs, datas, key, shift=0):
    ctx0, ln0, k, w, order = key
    k += shift
    occ = hit = 0
    if k + w > ln0:
        return 0, 0
    for log, data in zip(logs, datas):
        for i, (pos, ln, ctx) in enumerate(log):
            if ctx != ctx0 or ln != ln0:
                continue
            v = int.from_bytes(data[pos + k:pos + k + w], order)
            occ += 1
            hit += (v >= MIN_LEN and v in targets(log, i, pos + ln))
    return occ, hit


def run(name, logs, datas):
    h = len(logs) // 2
    LA, DA, LB, DB = logs[:h], datas[:h], logs[h:], datas[h:]
    S, V = learn(LA, DA)
    rules = [k for k, (o, m) in S.items() if o >= LEARN_MIN_OCC and m / o >= LEARN_MIN_SUPPORT]
    varying = [k for k in rules if len(V[k]) > 1]
    const = [k for k in rules if len(V[k]) == 1]
    rows = []
    for key in varying:
        o, h_ = evaluate_rule(LB, DB, key)
        if o < 3:
            continue
        co, ch = evaluate_rule(LB, DB, key, shift=1)
        rows.append((key, S[key][1] / S[key][0], h_ / o, o, ch / co if co else None))
    kept = []
    for r in sorted(rows, key=lambda r: (-r[2], -r[0][3], r[0][0], r[0][2])):
        a, b = r[0][2], r[0][2] + r[0][3]
        if any(q[0][0] == r[0][0] and q[0][1] == r[0][1] and a < q[0][2] + q[0][3] and q[0][2] < b for q in kept):
            continue
        kept.append(r)
    rows = sorted(kept, key=lambda r: (-r[3], r[0][0], r[0][2]))
    held = [r for r in rows if r[2] >= PASS_ACC]
    part = [r for r in rows if PART_ACC <= r[2] < PASS_ACC]
    ctrl = [r[4] for r in rows if r[4] is not None]
    print(f"\n{name}: навчання {len(LA)} файлів, перевірка {len(LB)}")
    print(f"  правил-кандидатів (збіг >= {LEARN_MIN_SUPPORT:.0%}): {len(rules)}; з постійним значенням (підозрілі): {len(const)}; зі змінним значенням: {len(varying)}")
    print(f"  полів довжини після злиття ширин: {len(rows)}; тримають >= {PASS_ACC:.0%}: {len(held)}, частково ({PART_ACC:.0%}-{PASS_ACC:.0%}): {len(part)}", end="")
    if rows:
        print(f"; середня точність {100 * sum(r[2] for r in rows) / len(rows):.1f} %", end="")
    if ctrl:
        print(f"; контроль (зсув на 1 байт) {100 * sum(ctrl) / len(ctrl):.1f} %", end="")
    print()
    print(f"  {'точка читання':38s}{'довж.':>6s}{'зсув':>5s}{'шир.':>5s}{'порядок':>8s}{'навч.':>7s}{'перев.':>8s}{'випадків':>9s}")
    for key, tr, te, o, _ in rows[:10]:
        print(f"  {key[0][:38]:38s}{key[1]:6d}{key[2]:5d}{key[3]:5d}{key[4]:>8s}{100 * tr:6.0f}%{100 * te:7.0f}%{o:9d}")
    return len(rows), len(held)


def main(fmts):
    import trace_lib as T
    files = T.collect_files()
    rng = random.Random(SEED)
    for c in fmts:
        if c not in T.FORMATS:
            continue
        lst = sorted(files[c])
        rng.shuffle(lst)
        logs, datas = [], []
        for p in lst:
            if len(logs) >= PER_CLASS:
                break
            try:
                if not (1024 <= p.stat().st_size <= MAX_BYTES):
                    continue
                d = p.read_bytes()
                lg = CTX.run_ctx(c, d)
            except Exception:
                continue
            if lg:
                logs.append(lg)
                datas.append(d)
        if len(logs) < 8:
            print(f"{c}: замало файлів")
            continue
        run(c, logs, datas)


if __name__ == "__main__":
    main(sys.argv[1:] or ["png", "gif", "ico", "wav", "gz", "docx"])
