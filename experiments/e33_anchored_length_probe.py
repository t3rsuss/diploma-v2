import ast
import collections
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import rebin as RB
from demo import evtx_reader as R

# Candidate discovery does not use truth.
stats = collections.defaultdict(lambda: [0, 0])
values = collections.defaultdict(set)
matches = collections.defaultdict(list)
inputs = []
samples = []

for path in sorted((ROOT / "data/corpus/evtx").glob("*.evtx")):
    data = path.read_bytes()
    raw_log = RB._trace_custom(R.parse_head, data)
    log = RB.INF2.merge_runs([(data, raw_log)])[0][1]
    samples.append((path.name, data, log))
    inputs.append({
        "file": path.name,
        "sha256": hashlib.sha256(data).hexdigest(),
    })

assert samples, "No development EVTX files"

for filename, data, log in samples:
    for i, (pos, width, ctx) in enumerate(log):
        if width not in (1, 2, 4) or i == 0:
            continue

        previous_pos, previous_size, previous_ctx = log[i - 1]
        if not (0 < previous_size <= RB.INF2.MAX_HEADER):
            continue
        if previous_pos + previous_size != pos:
            continue

        for order in (("little",) if width == 1 else ("little", "big")):
            key = (
                ctx, width, order,
                previous_ctx, previous_size,
            )
            stats[key][0] += 1
            value = int.from_bytes(data[pos:pos + width], order)
            endpoint = previous_pos + value
            if endpoint <= pos + width or endpoint > len(data):
                continue

            cursor = pos + width
            found = None
            for p, size, terminal_ctx in log[i + 1:i + 1 + RB.INF2.LOOK]:
                if p != cursor or size <= 0:
                    break
                cursor = p + size
                if cursor > endpoint:
                    break
                if cursor == endpoint:
                    if (
                        size == width
                        and int.from_bytes(data[p:cursor], order) == value
                    ):
                        found = (p, cursor, terminal_ctx)
                    break

            if found is not None:
                stats[key][1] += 1
                values[key].add(value)
                matches[key].append({
                    "file": filename,
                    "field": [pos, pos + width],
                    "block": [previous_pos, endpoint],
                    "trailer": [found[0], found[1]],
                    "trailer_context": found[2],
                    "value": value,
                })

accepted = []
for key, (occurrences, hits) in stats.items():
    support = hits / occurrences
    if (
        occurrences >= RB.INF2.RULE_MIN_OCC
        and support >= RB.INF2.RULE_MIN_SUPPORT
        and len(values[key]) >= RB.INF2.RULE_MIN_DISTINCT
    ):
        accepted.append((key, occurrences, hits, support))

# Truth is loaded only after discovery, for evaluation.
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

expected = set()
true_blocks = {}
for filename, data, _ in samples:
    fields = truth(data)
    for i in range(0, len(fields), 6):
        sig, size_field, ident, stamp, body, tail = fields[i:i + 6]
        iv = tuple(size_field[:2])
        expected.add((filename, *iv))
        true_blocks[(filename, *iv)] = [sig[0], tail[1]]

predicted = set()
wrong_blocks = []
rules = []

for key, occurrences, hits, support in accepted:
    records = matches[key]
    for item in records:
        field_key = (item["file"], *item["field"])
        predicted.add(field_key)
        if (
            field_key in true_blocks
            and item["block"] != true_blocks[field_key]
        ):
            wrong_blocks.append(item)

    rules.append({
        "key": list(key),
        "occurrences": occurrences,
        "hits": hits,
        "support": support,
        "distinct_matching_values": len(values[key]),
        "examples": records[:3],
    })

report = {
    "scope": (
        "Development EVTX only. Previous-read anchor and equal-value trailer. "
        "Whole-read integer candidates of width 1, 2 or 4. "
        "Truth used only after candidate discovery. "
        "Not integrated into inference and not a held-out evaluation."
    ),
    "inputs": inputs,
    "code_sha256": {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in (
            "experiments/e33_anchored_length_probe.py",
            "experiments/e20_infer2.py",
            "experiments/e27_evtx_structure_eval.py",
            "demo/evtx_reader.py",
        )
    },
    "accepted_rules": rules,
    "true_size_fields": len(expected),
    "correct_size_candidates": len(predicted & expected),
    "other_field_candidates": len(predicted - expected),
    "other_field_examples": [
        list(x) for x in sorted(predicted - expected)[:20]
    ],
    "wrong_block_intervals": wrong_blocks,
}

out = ROOT / "results/e33_anchored_length_probe.json"
out.write_text(
    json.dumps(report, ensure_ascii=False, indent=2),
    encoding="utf-8",
)

print("Files:", len(samples))
print("Accepted rules:", len(rules))
for rule in rules:
    print("\n", rule)
print("\nTrue size fields:", len(expected))
print("Correct size candidates:", len(predicted & expected))
print("Other field candidates:", len(predicted - expected))
print("Wrong block intervals:", len(wrong_blocks))
print("Saved:", out)
