import ast
import collections
import hashlib
import json
import pathlib
import struct
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import rebin as RB
from demo import evtx_reader as R

source = ROOT / "experiments/e27_evtx_structure_eval.py"
tree = ast.parse(source.read_text(encoding="utf-8-sig"))
nodes = [
    node for node in tree.body
    if isinstance(node, ast.FunctionDef) and node.name == "truth"
]
assert len(nodes) == 1
namespace = {"struct": struct}
exec(
    compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"),
    namespace,
)
truth = namespace["truth"]

counts = collections.defaultdict(collections.Counter)
contexts = collections.Counter()
failures = []
inputs = []

paths = sorted((ROOT / "data/corpus/evtx").glob("*.evtx"))
assert paths, "No development EVTX files"

for path in paths:
    data = path.read_bytes()
    raw_log = RB._trace_custom(R.parse_head, data)
    log = RB.INF2.merge_runs([(data, raw_log)])[0][1]

    by_interval = collections.defaultdict(list)
    for i, (p, size, ctx) in enumerate(log):
        by_interval[(p, p + size)].append((i, ctx))

    fields = truth(data)
    assert len(fields) % 6 == 0

    for offset in range(0, len(fields), 6):
        sig, size_field, ident, stamp, body, tail = fields[offset:offset + 6]
        start = sig[0]
        end = tail[1]
        cls = size_field[3]
        value = struct.unpack_from("<I", data, size_field[0])[0]
        stat = counts[cls]
        stat["records"] += 1

        checks = {
            "signature_read_present": bool(
                by_interval.get((sig[0], sig[1]))
            ),
            "size_read_present": bool(
                by_interval.get((size_field[0], size_field[1]))
            ),
            "start_plus_size_equals_end": start + value == end,
            "tail_read_present": bool(
                by_interval.get((tail[0], tail[1]))
            ),
            "tail_value_equals_size": (
                struct.unpack_from("<I", data, tail[0])[0] == value
            ),
        }

        for _, ctx in by_interval.get((sig[0], sig[1]), []):
            contexts[ctx] += 1

        candidates = by_interval.get(
            (size_field[0], size_field[1]), []
        )
        if candidates:
            i, _ = candidates[0]
            p, length, _ = log[i]
            _, sums, _ = RB.INF2.following(log, i, p + length)

            checks["prefix_match_offset_0"] = value in sums
            checks["prefix_match_offset_4"] = value - 4 in sums
            checks["prefix_match_offset_8"] = value - 8 in sums
            checks["previous_event_is_signature"] = (
                i > 0 and log[i - 1][:2] == (start, 4)
            )

        for name, ok in checks.items():
            stat[name] += int(ok)

        required = (
            "signature_read_present",
            "size_read_present",
            "start_plus_size_equals_end",
            "tail_read_present",
            "tail_value_equals_size",
            "previous_event_is_signature",
        )
        bad = [name for name in required if not checks.get(name, False)]
        if bad:
            failures.append({
                "file": path.name,
                "record_start": start,
                "class": cls,
                "failed_checks": bad,
            })

    inputs.append({
        "file": path.name,
        "sha256": hashlib.sha256(data).hexdigest(),
    })

report = {
    "scope": (
        "Development EVTX, first two chunks. Truth-assisted diagnostic only; "
        "not an inference algorithm and not a held-out evaluation. "
        "Offset matches use contiguous prefix sums from v2 following()."
    ),
    "commit": subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT,
        capture_output=True, text=True, check=True,
    ).stdout.strip(),
    "inputs": inputs,
    "code_sha256": {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in (
            "experiments/e20_infer2.py",
            "experiments/e27_evtx_structure_eval.py",
            "experiments/e32_evtx_relation_probe.py",
            "demo/evtx_reader.py",
        )
    },
    "by_record_position": {
        cls: dict(stat) for cls, stat in counts.items()
    },
    "signature_contexts": dict(contexts),
    "structural_check_failures": failures,
}

out = ROOT / "results/e32_evtx_relation_probe.json"
out.write_text(
    json.dumps(report, ensure_ascii=False, indent=2),
    encoding="utf-8",
)

print("Files:", len(inputs))
for cls, stat in counts.items():
    print("\nPOSITION:", cls)
    for name, value in stat.items():
        print(" ", name, ":", value)
print("\nSignature contexts:", dict(contexts))
print("Structural check failures:", len(failures))
for failure in failures[:10]:
    print(failure)
print("Saved:", out)
