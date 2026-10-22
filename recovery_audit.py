def audit_intervals(intervals, size):
    if size < 0:
        raise ValueError("Negative file size")

    events = {0: 0, size: 0}
    invalid = []

    for index, (start, end) in enumerate(intervals):
        if not 0 <= start < end <= size:
            invalid.append({
                "index": index,
                "start": start,
                "end": end,
            })
            continue

        events[start] = events.get(start, 0) + 1
        events[end] = events.get(end, 0) - 1

    points = sorted(events)
    active = covered = overlap_bytes = 0
    gaps, overlaps = [], []

    def append_span(items, start, end):
        if items and items[-1]["end"] == start:
            items[-1]["end"] = end
        else:
            items.append({"start": start, "end": end})

    for start, end in zip(points, points[1:]):
        active += events[start]

        if active == 0:
            append_span(gaps, start, end)
        else:
            covered += end - start

        if active > 1:
            overlap_bytes += end - start
            append_span(overlaps, start, end)

    return {
        "file_size": size,
        "covered_bytes": covered,
        "coverage": covered / size if size else 0.0,
        "overlap_bytes": overlap_bytes,
        "uncovered_intervals": gaps,
        "overlap_intervals": overlaps,
        "invalid_intervals": invalid,
    }
