import collections
import pathlib
import random
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import e18_context as CTX

MAX_HDR, MIN_LEN, LOOK = 64, 1, 40
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



def select_rules(logs, datas):
    S, V = learn(logs, datas)
    candidates_all = [
        key for key, (occ, hit) in S.items()
        if occ >= LEARN_MIN_OCC and hit / occ >= LEARN_MIN_SUPPORT
    ]
    varying = [key for key in candidates_all if len(V[key]) > 1]
    constants = [key for key in candidates_all if len(V[key]) == 1]
    varying.sort(key=lambda key: (
        -S[key][1] / S[key][0],
        -S[key][0],
        key
    ))
    return varying, constants, S


def overlaps(a, b):
    return (
        a[:2] == b[:2]
        and a[2] < b[2] + b[3]
        and b[2] < a[2] + a[3]
    )


def run(name, logs, datas):
    h = len(logs) // 2
    LA, DA = logs[:h], datas[:h]
    LB, DB = logs[h:], datas[h:]

    rules, constants, S = select_rules(LA, DA)
    rows = []
    total_occ = total_hit = 0
    evaluated = passed = 0
    ctrl_occ = ctrl_hit = 0

    print(f"\n{name}: навчання {len(LA)}, перевірка {len(LB)} файлів")
    print(
        f"  змінних гіпотез: {len(rules)}; "
        f"сталих кандидатів, не включених до перевірки: {len(constants)}"
    )
    print("  Вибір гіпотез виконано тільки на навчальній частині.")
    print("  Перекриті гіпотези збережено; це не кількість різних полів.")

    for key in rules:
        occ, hit = evaluate_rule(LB, DB, key)
        co, ch = evaluate_rule(LB, DB, key, shift=1)
        ambiguous = any(
            other != key and overlaps(key, other)
            for other in rules
        )
        train_occ, train_hit = S[key]
        rate = hit / occ if occ else None

        rows.append((key, train_hit / train_occ, occ, hit, rate, ambiguous))
        total_occ += occ
        total_hit += hit
        ctrl_occ += co
        ctrl_hit += ch

        if occ >= 3:
            evaluated += 1
            passed += rate >= PASS_ACC

    print(
        f"  гіпотез із >=3 перевірочними випадками: {evaluated}; "
        f"із часткою виконання >= {PASS_ACC:.0%}: {passed}"
    )

    if total_occ:
        print(
            f"  виконано перевірок: {total_hit}/{total_occ} "
            f"({100 * total_hit / total_occ:.1f} %)"
        )
        print("  Агрегат враховує перекриті гіпотези, тому не є точністю полів.")

    if ctrl_occ:
        print(
            f"  контроль зі зсувом +1: {ctrl_hit}/{ctrl_occ} "
            f"({100 * ctrl_hit / ctrl_occ:.1f} %)"
        )
    else:
        print("  контроль зі зсувом +1: немає допустимих перевірок")

    print(
        f"  {'точка читання':38s}"
        f"{'чит.':>6s}{'зсув':>5s}{'шир.':>5s}"
        f"{'порядок':>8s}{'навч.':>8s}"
        f"{'збіг/усі':>12s}{'перев.':>9s}  перекриття"
    )

    for key, tr, occ, hit, rate, ambiguous in rows:
        result = f"{100 * rate:.1f}%" if rate is not None else "n/a"
        counts = f"{hit}/{occ}"
        print(
            f"  {key[0][:38]:38s}"
            f"{key[1]:6d}{key[2]:5d}{key[3]:5d}"
            f"{key[4]:>8s}{100 * tr:7.1f}%"
            f"{counts:>12s}{result:>9s}  "
            f"{'так' if ambiguous else 'ні'}"
        )

    return len(rules), passed


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
