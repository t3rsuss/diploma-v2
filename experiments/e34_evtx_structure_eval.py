import collections, hashlib, json, pathlib, struct, subprocess, sys, time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import rebin as RB
from demo import evtx_reader as R
import e34_combined_lengths as V4


def truth(data):
    out = []
    for c in range(2):
        base = 4096 + 65536 * c
        if data[base:base + 8] != b"ElfChnk\x00":
            break
        last = struct.unpack_from("<I", data, base + 44)[0]
        if last < 512:
            continue
        pos, idx = base + 512, 0
        while True:
            size = struct.unpack_from("<I", data, pos + 4)[0]
            is_last = pos - base >= last
            if idx == 0 and is_last:
                cls = "only"
            elif idx == 0:
                cls = "first"
            elif is_last:
                cls = "last"
            else:
                cls = "middle"
            out += [(pos, pos + 4, "sig", cls), (pos + 4, pos + 8, "size", cls),
                    (pos + 8, pos + 16, "id", cls), (pos + 16, pos + 24, "time", cls),
                    (pos + 24, pos + size - 4, "body", cls),
                    (pos + size - 4, pos + size, "tail", cls)]
            if is_last:
                break
            pos += size
            idx += 1
    return out


files = sorted((ROOT / "data/corpus/evtx").glob("*.evtx"))
items = []
for p in files:
    data = p.read_bytes()
    items.append((data, RB._trace_custom(R.parse_head, data)))
print("files:", len(items), "| events:", sum(len(l) for _, l in items), flush=True)

t0 = time.time()
inferred = V4.infer2(items)
seconds = round(time.time() - t0, 1)
assert len(inferred) == len(items)
print("infer2 seconds:", seconds, flush=True)

stat = collections.defaultdict(collections.Counter)
for (data, log), fields in zip(items, inferred):
    by_iv = {(a, b): role for a, b, role in fields}
    for a, b, kind, cls in truth(data):
        role = by_iv.get((a, b)) or "no exact interval"
        stat[(kind, cls)][role] += 1

for kind in ("sig", "size", "id", "time", "body", "tail"):
    for cls in ("first", "middle", "last", "only"):
        c = stat.get((kind, cls))
        if c:
            print(f"{kind:5s} {cls:7s} n={sum(c.values()):5d}  {dict(c)}")

commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                        capture_output=True, text=True).stdout.strip()
out = ROOT / "results/e34_evtx_structure_eval.json"
out.write_text(json.dumps({
    "scope": ("Joint inference over all local EVTX files, first two chunks only "
              "(demo/evtx_reader.py:parse_head). Ground truth is the author's "
              "reading of the public EVTX layout. Diagnostic development run, "
              "not a held-out evaluation."),
    "commit": commit,
    "files": len(items),
    "events": sum(len(l) for _, l in items),
    "infer2_seconds": seconds,
    "infer2_sha256": hashlib.sha256((ROOT / "experiments/e34_combined_lengths.py").read_bytes()).hexdigest(),
    "reader_sha256": hashlib.sha256((ROOT / "demo/evtx_reader.py").read_bytes()).hexdigest(),
    "base_sha256": hashlib.sha256(
        (ROOT / "experiments/e30_local_markers.py").read_bytes()
    ).hexdigest(),
    "evaluator_sha256": hashlib.sha256(
        pathlib.Path(__file__).read_bytes()
    ).hexdigest(),
    "anchored_rules": V4.ANCHORED_RULES,
    "anchored_evidence_count": len(V4.ANCHORED_EVIDENCE),
    "roles_by_field_and_position": {f"{k}/{c}": dict(v) for (k, c), v in stat.items()},
}, indent=2), encoding="utf-8")
print("Saved:", out)
