"""Experimental local-marker and anchored repeated-length inference."""
import collections

import e30_local_markers as BASE

MARKER_VALUES = BASE.MARKER_VALUES
ANCHORED_RULES = []
ANCHORED_EVIDENCE = []
LENGTH_ROLE = "\u0434\u043e\u0432\u0436\u0438\u043d\u0430"


def anchored_candidates(samples):
    stats = collections.defaultdict(lambda: [0, 0])
    values = collections.defaultdict(set)
    matches = collections.defaultdict(list)

    for file_index, (data, log) in enumerate(samples):
        for i, (pos, width, ctx) in enumerate(log):
            if width not in (1, 2, 4) or i == 0:
                continue
            previous_pos, previous_size, previous_ctx = log[i - 1]
            if not 0 < previous_size <= BASE.MAX_HEADER:
                continue
            if previous_pos + previous_size != pos:
                continue

            orders = ("little",) if width == 1 else ("little", "big")
            for order in orders:
                key = (ctx, width, order, previous_ctx, previous_size)
                stats[key][0] += 1
                value = int.from_bytes(data[pos:pos + width], order)
                endpoint = previous_pos + value
                if endpoint <= pos + width or endpoint > len(data):
                    continue

                cursor = pos + width
                for p, size, terminal_ctx in log[i + 1:i + 1 + BASE.LOOK]:
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
                            stats[key][1] += 1
                            values[key].add(value)
                            matches[key].append({
                                "file_index": file_index,
                                "field": (pos, pos + width),
                                "block": (previous_pos, endpoint),
                                "trailer": (p, cursor),
                                "trailer_context": terminal_ctx,
                                "value": value,
                            })
                        break

    rules, evidence = [], []
    for key, (occurrences, hits) in stats.items():
        support = hits / occurrences
        if (
            occurrences >= BASE.RULE_MIN_OCC
            and support >= BASE.RULE_MIN_SUPPORT
            and len(values[key]) >= BASE.RULE_MIN_DISTINCT
        ):
            rules.append({
                "key": key,
                "occurrences": occurrences,
                "hits": hits,
                "support": support,
                "distinct_matching_values": len(values[key]),
            })
            evidence.extend(matches[key])
    return rules, evidence


def infer2(samples):
    samples = list(samples)
    output = BASE.infer2(samples)
    merged = BASE.merge_runs(samples)
    rules, evidence = anchored_candidates(merged)

    ANCHORED_RULES.clear()
    ANCHORED_RULES.extend(rules)
    ANCHORED_EVIDENCE.clear()
    ANCHORED_EVIDENCE.extend(evidence)

    accepted = collections.defaultdict(set)
    for item in evidence:
        accepted[item["file_index"]].add(item["field"])

    result = []
    for index, fields in enumerate(output):
        result.append([
            (a, b, LENGTH_ROLE if (a, b) in accepted[index] else role)
            for a, b, role in fields
        ])
    return result
