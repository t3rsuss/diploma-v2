import collections, hashlib, io, json, pathlib, struct, subprocess, sys, time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import rebin as RB
from demo import dns_reader as R


def truth(m):
    out = []
    pos = 0

    def add(n, kind):
        nonlocal pos
        out.append((pos, pos + n, kind))
        pos += n

    def name(prefix):
        while True:
            n = m[pos]
            if n == 0:
                add(1, prefix + "_end")
                return
            if n & 0xC0 == 0xC0:
                add(1, prefix + "_ptr1")
                add(1, prefix + "_ptr2")
                return
            add(1, prefix + "_len")
            add(n, prefix + "_label")

    add(2, "id")
    add(2, "flags")
    qd, an, ns, ar = struct.unpack_from(">HHHH", m, 4)
    add(2, "qdcount")
    add(2, "ancount")
    add(2, "nscount")
    add(2, "arcount")
    for _ in range(qd):
        name("qname")
        add(2, "qtype")
        add(2, "qclass")
    for _ in range(an + ns + ar):
        name("rr")
        add(2, "rr_type")
        add(2, "rr_class")
        add(4, "rr_ttl")
        rdlen = struct.unpack_from(">H", m, pos)[0]
        add(2, "rr_rdlen")
        if rdlen:
            add(rdlen, "rr_rdata")
    return out


items = []
for p in sorted((ROOT / "data/corpus/dns").glob("*.dns")):
    data = p.read_bytes()
    bio = io.BytesIO(data)
    try:
        R.parse_file(bio)
        if bio.tell() != len(data):
            continue
    except Exception:
        continue
    items.append((data, RB._trace_custom(R.parse_file, data)))

queries = sum(1 for d, _ in items if not d[2] & 0x80)
print("messages:", len(items), "| queries:", queries, "| responses:", len(items) - queries,
      "| events:", sum(len(l) for _, l in items), flush=True)

t0 = time.time()
inferred = RB.INF2.infer2(items)
seconds = round(time.time() - t0, 2)
assert len(inferred) == len(items)
print("infer2 seconds:", seconds)

stat = collections.defaultdict(collections.Counter)
for (data, log), fields in zip(items, inferred):
    by_iv = {(a, b): role for a, b, role in fields}
    for a, b, kind in truth(data):
        stat[kind][by_iv.get((a, b)) or "no exact interval"] += 1

for kind in sorted(stat, key=lambda k: -sum(stat[k].values())):
    c = stat[kind]
    print(f"{kind:12s} n={sum(c.values()):5d}  {dict(c)}")

commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                        capture_output=True, text=True).stdout.strip()
out = ROOT / "results/dns_structure_eval.json"
out.write_text(json.dumps({
    "scope": ("Real DNS messages captured with pktmon on the author's machine "
              "(6 names x 5 record types), deduplicated by bytes. Joint inference. "
              "Ground truth: RFC 1035 layout read by the author; the reader does not "
              "resolve compression pointers. Development run, not held-out."),
    "commit": commit,
    "messages": len(items),
    "queries": queries,
    "infer2_seconds": seconds,
    "infer2_sha256": hashlib.sha256((ROOT / "experiments/e20_infer2.py").read_bytes()).hexdigest(),
    "reader_sha256": hashlib.sha256((ROOT / "demo/dns_reader.py").read_bytes()).hexdigest(),
    "roles_by_field": {k: dict(v) for k, v in stat.items()},
}, indent=2), encoding="utf-8")
print("Saved:", out)
