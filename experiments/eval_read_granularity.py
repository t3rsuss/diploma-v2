import collections, json, pathlib, random, statistics, subprocess, sys
from io import BytesIO

import trace_lib as T
from kaitaistruct import KaitaiStream

ROOT = pathlib.Path(__file__).resolve().parents[1]
SEED = 42
rng = random.Random(SEED)
files = T.collect_files()
results = {}

for fmt in ("gif", "png", "ico", "wav", "gz"):
    mod, cls = T.FORMATS[fmt]
    Parser = T.load(mod, cls)
    paths = sorted(p for p in files[fmt] if p.exists())
    rng.shuffle(paths)
    shared = total = ok = 0
    counts = []
    fail = collections.Counter()
    for p in paths[:40]:
        try:
            if p.stat().st_size > 3_000_000:
                continue
            data = p.read_bytes()
        except OSError:
            continue
        try:
            log = T.run_reader(fmt, data)
        except Exception as e:
            fail["reader:" + type(e).__name__] += 1
            continue
        try:
            obj = Parser(KaitaiStream(BytesIO(data)))
            obj._read()
            spans = []
            T.walk(obj, 0, spans, {id(obj)})
        except Exception as e:
            fail["kaitai:" + type(e).__name__] += 1
            continue
        K = {s for s, e, _ in spans} | {e for s, e, _ in spans}
        K = {x for x in K if 0 < x < len(data)}
        B = {a for a, n in log} | {a + n for a, n in log}
        shared += len(K & B)
        total += len(K)
        counts.append(len(K))
        ok += 1
    results[fmt] = {
        "files": ok,
        "kaitai_boundaries_total": total,
        "shared_with_read_boundaries": shared,
        "share": round(shared / total, 4) if total else None,
        "kaitai_boundaries_median": statistics.median(counts) if counts else None,
        "failures": dict(fail),
    }
    print(fmt, results[fmt], flush=True)

commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                        capture_output=True, text=True).stdout.strip()
out = ROOT / "results/read_granularity.json"
out.write_text(json.dumps({
    "scope": ("Share of Kaitai field boundaries that coincide with reader "
              "read boundaries. Local corpus on the author machine; not a "
              "ceiling for infer2, which also splits by cross-sample variance."),
    "seed": SEED,
    "max_files_per_format": 40,
    "commit": commit,
    "results": results,
}, indent=2), encoding="utf-8")
print("Saved:", out)
