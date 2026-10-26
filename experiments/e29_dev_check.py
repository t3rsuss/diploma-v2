import ast
import collections
import hashlib
import io
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import rebin as RB
from demo import dns_reader as R
import e29_infer3 as V3

LEN = "\u0434\u043e\u0432\u0436\u0438\u043d\u0430"
LENGTH_KINDS = {"qname_len", "rr_len", "rr_rdlen"}

source = ROOT / "experiments/e28_dns_structure_eval.py"
tree = ast.parse(source.read_text(encoding="utf-8-sig"))
nodes = [
    node for node in tree.body
    if isinstance(node, ast.FunctionDef) and node.name == "truth"
]
assert len(nodes) == 1
namespace = {"struct": __import__("struct")}
module = ast.Module(body=nodes, type_ignores=[])
exec(compile(module, str(source), "exec"), namespace)
truth = namespace["truth"]

items, names, skipped = [], [], []
for path in sorted((ROOT / "data/corpus/dns").glob("*.dns")):
    data = path.read_bytes()
    try:
        stream = io.BytesIO(data)
        R.parse_file(stream)
        if stream.tell() != len(data):
            raise ValueError("Reader did not consume the whole message")
        log = RB._trace_custom(R.parse_file, data)
        expected = truth(data)
        assert expected and expected[-1][1] == len(data)
    except Exception as exc:
        skipped.append({
            "file": path.name,
            "error": type(exc).__name__ + ": " + str(exc),
        })
        continue
    names.append(path.name)
    items.append((data, log))

assert items, "No accepted development messages"
outputs = {
    "v2": RB.INF2.infer2(items),
    "v3_markers": V3.infer2(items),
}
assert all(len(output) == len(items) for output in outputs.values())

summary = {}
for version, output in outputs.items():
    by_kind = collections.defaultdict(collections.Counter)
    true_lengths = detected = missing = 0
    false_lengths = []

    for name, (data, _), fields in zip(names, items, output):
        expected = truth(data)
        intervals = {(a, b): role for a, b, role in fields}
        valid_lengths = {
            (a, b) for a, b, kind in expected if kind in LENGTH_KINDS
        }
        true_lengths += len(valid_lengths)
        detected += sum(intervals.get(iv) == LEN for iv in valid_lengths)

        for a, b, kind in expected:
            role = intervals.get((a, b), "no exact interval")
            by_kind[kind][role] += 1
            missing += (a, b) not in intervals

        for a, b, role in fields:
            if role == LEN and (a, b) not in valid_lengths:
                false_lengths.append({"file": name, "start": a, "end": b})

    summary[version] = {
        "true_length_fields": true_lengths,
        "correct_length_labels": detected,
        "length_recall": detected / true_lengths if true_lengths else None,
        "false_length_labels": len(false_lengths),
        "false_length_examples": false_lengths[:20],
        "missing_exact_intervals": missing,
        "roles_by_field": {k: dict(v) for k, v in by_kind.items()},
    }

changes = collections.Counter()
changed_intervals = 0
for first, second in zip(outputs["v2"], outputs["v3_markers"]):
    a = {(start, end): role for start, end, role in first}
    b = {(start, end): role for start, end, role in second}
    changed_intervals += len(set(a) ^ set(b))
    for iv in set(a) | set(b):
        if a.get(iv) != b.get(iv):
            changes[(a.get(iv), b.get(iv))] += 1

report = {
    "scope": "Development DNS only; marker extension only; no held-out data.",
    "commit": subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT,
        capture_output=True, text=True, check=True,
    ).stdout.strip(),
    "messages": len(items),
    "skipped": skipped,
    "sha256": {
        name: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
        for name, path in {
            "v2": "experiments/e20_infer2.py",
            "v3_markers": "experiments/e29_infer3.py",
            "reader": "demo/dns_reader.py",
            "truth_source": "experiments/e28_dns_structure_eval.py",
            "evaluator": "experiments/e29_dev_check.py",
        }.items()
    },
    "summary": summary,
    "interval_symmetric_difference_count": changed_intervals,
    "role_changes": [
        {"from": old, "to": new, "count": count}
        for (old, new), count in changes.items()
    ],
    "marker_rules": [
        {"key": list(key), "excluded_values": sorted(values)}
        for key, values in V3.MARKER_VALUES.items()
    ],
}

out = ROOT / "results/v3_markers_dns_dev.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(
    json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8",
)

print("Accepted:", len(items), "| skipped:", len(skipped))
for version, stats in summary.items():
    print("\n" + version)
    print("True lengths:", stats["true_length_fields"])
    print("Correct length labels:", stats["correct_length_labels"])
    print("False length labels:", stats["false_length_labels"])
    print("Missing exact intervals:", stats["missing_exact_intervals"])
    for kind, counts in stats["roles_by_field"].items():
        print(" ", kind, counts)
print("\nInterval differences:", changed_intervals)
print("Role changes:", report["role_changes"])
print("Marker rules:", report["marker_rules"])
print("Saved:", out)
