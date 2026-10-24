import hashlib
import json
import pathlib
import random
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.unknown import infer_records

SEED = 731
rng = random.Random(SEED)


def make_case(tw, lw, order, counter, constant=False, long_prefix=False):
    count = rng.randint(3 if counter else 4, 10)
    prefix_size = 80 if long_prefix else rng.randint(6, 30)
    prefix = bytearray(rng.randbytes(prefix_size))

    if counter:
        width = rng.choice((2, 4))
        offset = rng.randint(0, prefix_size - width)
        prefix[offset:offset + width] = count.to_bytes(width, order)

    lengths = [
        16 if constant else rng.randint(8, 200)
        for _ in range(count)
    ]
    if not constant and len(set(lengths)) == 1:
        lengths[-1] = 8 if lengths[0] != 8 else 9

    if counter:
        upper = min(5000, (1 << (8 * tw)) - 1)
        tags = rng.sample(range(1, upper + 1), count)
    else:
        tags = [1 + index % 2 for index in range(count)]

    data = bytes(prefix)
    expected = []

    for tag, length in zip(tags, lengths):
        start = len(data)
        type_end = start + tw
        payload_start = type_end + lw
        data += tag.to_bytes(tw, order)
        data += length.to_bytes(lw, order)
        data += rng.randbytes(length)
        expected.append((start, type_end, payload_start, len(data)))

    return data, expected


def exact_rank(search, expected, tw, lw, order):
    for rank, candidate in enumerate(search["candidates"], 1):
        spans = [
            (
                rec["start"], rec["type_end"],
                rec["payload_start"], rec["end"],
            )
            for rec in candidate["records"]
        ]
        if (
            candidate["type_width"] == tw
            and candidate["length_width"] == lw
            and candidate["byte_order"] == order
            and spans == expected
        ):
            return rank
    return None


def main():
    changed = subprocess.run(
        ["git", "diff", "--quiet", "HEAD", "--", "src/unknown.py"],
        cwd=ROOT,
    )
    if changed.returncode != 0:
        raise SystemExit(
            "Algorithm differs from HEAD. Freeze it before evaluation."
        )

    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    layouts = [
        ("le_counter", 1, 2, "little", True, False, False, 20),
        ("be_counter", 2, 4, "big", True, False, False, 20),
        ("le_no_counter", 1, 2, "little", False, False, False, 20),
        ("be_no_counter", 2, 2, "big", False, False, False, 20),
        ("constant_lengths", 1, 2, "little", True, True, False, 10),
        ("prefix_outside_search", 1, 2, "little", True, False, True, 10),
    ]

    rows = []
    summaries = {}

    for name, tw, lw, order, counter, constant, long_prefix, number in layouts:
        group_rows = []

        for index in range(number):
            data, expected = make_case(
                tw, lw, order, counter, constant, long_prefix,
            )
            search = infer_records(data)
            rank = exact_rank(search, expected, tw, lw, order)

            row = {
                "group": name,
                "index": index,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
                "expected_records": len(expected),
                "correct_rank": rank,
                "candidate_count": len(search["candidates"]),
                "truncated": search["search_truncated"],
            }
            rows.append(row)
            group_rows.append(row)

        summaries[name] = {
            "files": number,
            "top1_exact": sum(
                r["correct_rank"] == 1 for r in group_rows
            ),
            "exact_among_returned": sum(
                r["correct_rank"] is not None for r in group_rows
            ),
            "truncated": sum(r["truncated"] for r in group_rows),
        }

        print(name, json.dumps(summaries[name]))

    controls = []

    for index in range(20):
        size = rng.randint(512, 8192)
        words = [b"alpha", b"node", b"cache", b"value", b"service"]
        text = b" ".join(
            rng.choice(words) for _ in range(size // 4 + 1)
        )

        cases = {
            "random": rng.randbytes(size),
            "zeros": bytes(size),
            "periodic_bytes": (
                bytes(range(256)) * ((size + 255) // 256)
            )[:size],
            "ascii_text": text[:size],
        }

        for kind, data in cases.items():
            search = infer_records(data)
            controls.append({
                "kind": kind,
                "index": index,
                "size": len(data),
                "has_candidates": bool(search["candidates"]),
                "has_counter_evidence": any(
                    c.get("count_evidence")
                    for c in search["candidates"]
                ),
                "truncated": search["search_truncated"],
            })

    control_summary = {}

    for kind in ("random", "zeros", "periodic_bytes", "ascii_text"):
        group = [r for r in controls if r["kind"] == kind]
        control_summary[kind] = {
            "files": len(group),
            "with_candidates": sum(
                r["has_candidates"] for r in group
            ),
            "with_counter_evidence": sum(
                r["has_counter_evidence"] for r in group
            ),
            "truncated": sum(r["truncated"] for r in group),
        }

    print("controls")
    print(json.dumps(control_summary, indent=2))

    output = ROOT / "results/record_generalization_v2.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps({
            "scope": (
                "New synthetic development check after freezing the algorithm. "
                "Not an independent real-format benchmark."
            ),
            "seed": SEED,
            "commit": commit,
            "algorithm_sha256": hashlib.sha256(
                (ROOT / "src/unknown.py").read_bytes()
            ).hexdigest(),
            "summary": summaries,
            "control_summary": control_summary,
            "files": rows,
            "controls": controls,
        }, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print("Saved:", output)


if __name__ == "__main__":
    main()
