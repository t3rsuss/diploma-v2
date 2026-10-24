"""Evidence for length hypotheses; does not assign field roles."""
import e20_infer2 as INF


def _explain_one(merged, rules, data, log, cache):
    evidence = []

    for index, (pos, length, context) in enumerate(log):
        for offset, width, order, _ in rules.get((context, length), ()):
            value = INF.read_value(data, pos, offset, width, order)
            start, sums, singles = INF.following(
                log, index, pos + length,
            )

            target = None
            relation = "no_match_in_this_file"
            if value is not None and value >= INF.MIN_VAL:
                if value in sums:
                    target = [start, start + value]
                    relation = "following_contiguous_reads"
                else:
                    for p, size in singles:
                        if size == value:
                            target = [p, p + size]
                            relation = "nearby_single_read"
                            break

            key = (context, length, offset, width, order)
            if key not in cache:
                occurrences = matches = 0
                matched_files = set()
                values = set()

                for file_index, (raw, events) in enumerate(merged):
                    for i, (p, size, ctx) in enumerate(events):
                        if (ctx, size) != (context, length):
                            continue
                        v = INF.read_value(raw, p, offset, width, order)
                        _, totals, separate = INF.following(events, i, p + size)
                        occurrences += 1
                        if v is not None:
                            values.add(v)
                        if (
                            v is not None
                            and v >= INF.MIN_VAL
                            and (v in totals or any(n == v for _, n in separate))
                        ):
                            matches += 1
                            matched_files.add(file_index)

                cache[key] = (
                    occurrences, matches, matched_files, values,
                )
            occurrences, matches, matched_files, values = cache[key]

            evidence.append({
                "field": [pos + offset, pos + offset + width],
                "hypothesis": "length",
                "context": context,
                "encoding": order,
                "width_bytes": width,
                "value": value,
                "related_interval": target,
                "relation": relation,
                "local_read_match": target is not None,
                "interpretation": (
                    "Гіпотеза за вибіркою; є числовий збіг із читаннями цього файла."
                    if target is not None else
                    "Гіпотеза за вибіркою; збігу з читаннями цього файла не знайдено."
                ),
                "matching_events": matches,
                "checked_events": occurrences,
                "event_support": matches / occurrences if occurrences else 0.0,
                "files_with_matching_events": len(matched_files),
                "distinct_values": len(values),
            })

    return evidence


def explain_lengths(samples):
    merged = INF.merge_runs(samples)
    rules = INF.learn_rules(merged)
    cache = {}
    return [
        _explain_one(merged, rules, data, log, cache)
        for data, log in merged
    ]
