"""Single-file observations; does not recover a confirmed format schema."""
import collections
import math
import re


def _entropy(data):
    n = len(data)
    if not n:
        return 0.0
    return -sum(
        (count / n) * math.log2(count / n)
        for count in collections.Counter(data).values()
    )


def _extract(pattern, data, limit, text=False):
    items = []
    for match in pattern.finditer(data):
        if len(items) >= limit:
            return items, True
        item = {"start": match.start(), "end": match.end()}
        if text:
            item["preview"] = match.group()[:80].decode("ascii")
            item["preview_truncated"] = match.end() - match.start() > 80
        items.append(item)
    return items, False


def analyze_unknown(data, max_regions=2048, max_items=100):
    if max_regions < 1 or max_items < 1:
        raise ValueError("Observation limits must be positive")

    n = len(data)
    window = max(256, (n + max_regions - 1) // max_regions)
    regions = []

    for start in range(0, n, window):
        block = data[start:start + window]
        size = len(block)
        zeros = block.count(0) / size
        printable = sum(32 <= value <= 126 for value in block) / size
        entropy = _entropy(block)

        if zeros == 1:
            kind = "zero_filled"
        elif size >= 16 and printable >= 0.85:
            kind = "ascii_like"
        elif size >= 256 and entropy >= 7.2:
            kind = "high_entropy"
        else:
            kind = "mixed"

        regions.append({
            "start": start,
            "end": start + size,
            "size": size,
            "entropy": round(entropy, 4),
            "zero_fraction": round(zeros, 4),
            "ascii_fraction": round(printable, 4),
            "observation": kind,
        })

    strings, strings_limited = _extract(
        re.compile(rb"[\x20-\x7e]{4,}"), data, max_items, text=True,
    )
    zeros, zeros_limited = _extract(
        re.compile(rb"\x00{8,}"), data, max_items,
    )

    candidates = []
    for offset in range(min(64, n)):
        for width in (2, 4):
            end = offset + width
            if end > n:
                continue
            for order in ("little", "big"):
                value = int.from_bytes(data[offset:end], order)
                if value < 1:
                    continue
                if value == n:
                    relation = "matches_file_size"
                elif value == n - end:
                    relation = "matches_bytes_after_field"
                else:
                    continue
                candidates.append({
                    "start": offset,
                    "end": end,
                    "width": width,
                    "encoding": order,
                    "value": value,
                    "relation": relation,
                })

    return {
        "method": "single_file_observations_v1",
        "size": n,
        "window_bytes": window,
        "profile": regions,
        "ascii_strings": strings,
        "ascii_strings_limited": strings_limited,
        "zero_runs": zeros,
        "zero_runs_limited": zeros_limited,
        "numeric_candidates": candidates,
        "limitations": [
            "Profile windows are computational windows, not inferred fields.",
            "Numeric matches may be coincidental and can overlap.",
            "Only 2/4-byte integer candidates starting in the first 64 bytes are checked.",
            "ASCII extraction does not cover all text encodings.",
            "High entropy does not establish compression, encryption, or maliciousness.",
            "No reader or reference format schema is used.",
        ],
    }
