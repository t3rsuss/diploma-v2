import random

import pytest

from src.unknown import infer_records


def make_records(type_width, length_width, order, trailer=b""):
    data = b"PREFIX!"
    expected = []
    for index, size in enumerate((5, 13, 27, 41)):
        start = len(data)
        data += (1 + index % 2).to_bytes(type_width, order)
        data += size.to_bytes(length_width, order)
        data += bytes([180 + index]) * size
        expected.append((start, len(data)))
    return data + trailer, expected


@pytest.mark.parametrize(
    "tw,lw,order",
    [(1, 1, "little"), (1, 2, "big"), (2, 4, "little")],
)
def test_expected_record_chain_is_a_candidate(tw, lw, order):
    data, expected = make_records(tw, lw, order)
    result = infer_records(data)

    matching = [
        c for c in result["candidates"]
        if c["start"] == 7
        and c["type_width"] == tw
        and c["length_width"] == lw
        and c["byte_order"] == order
        and [
            (r["start"], r["end"]) for r in c["records"]
        ] == expected
    ]
    assert matching

    for candidate in result["candidates"]:
        assert 0 <= candidate["start"] < candidate["end"] <= len(data)
        for record in candidate["records"]:
            assert (
                record["end"] - record["payload_start"]
                == record["length"]
            )
        assert all(
            left["end"] == right["start"]
            for left, right in zip(
                candidate["records"], candidate["records"][1:],
            )
        )


@pytest.mark.parametrize("data", [b"", bytes(4096), b"A" * 4096])
def test_simple_negative_controls(data):
    assert infer_records(data)["candidates"] == []


def test_one_seeded_random_control():
    data = random.Random(42).randbytes(4096)
    assert infer_records(data)["candidates"] == []


def test_search_budget():
    data, _ = make_records(1, 2, "little")
    result = infer_records(data, max_steps=1)

    assert result["search_truncated"] is True
    assert result["steps"] == 1


def test_trailer_is_reported_as_unparsed():
    data, _ = make_records(
        1, 2, "little", trailer=b"\xff" * 4,
    )
    result = infer_records(data)

    assert any(
        c["start"] == 7
        and c["type_width"] == 1
        and c["length_width"] == 2
        and c["byte_order"] == "little"
        and c["unparsed_suffix"] == 4
        and c["record_count"] == 4
        for c in result["candidates"]
    )


def _three_record_sample(counter_bytes):
    prefix = b"\xa9\xf3" + counter_bytes + b"\x99"
    data = prefix
    expected = []

    for tag, size in enumerate((7, 19, 31), 1):
        start = len(data)
        data += bytes([tag]) + size.to_bytes(2, "little")
        data += bytes([180 + tag]) * size
        expected.append((start, len(data)))

    return data, len(prefix), expected


def _matching_three_record_candidates(result, start, expected):
    return [
        c for c in result["candidates"]
        if c["start"] == start
        and c["type_width"] == 1
        and c["length_width"] == 2
        and c["byte_order"] == "little"
        and [(r["start"], r["end"]) for r in c["records"]] == expected
    ]


def test_three_unique_records_with_counter():
    data, start, expected = _three_record_sample(
        (3).to_bytes(2, "little")
    )
    result = infer_records(data)
    matching = _matching_three_record_candidates(result, start, expected)

    assert matching
    assert {
        "start": 2, "end": 4, "encoding": "little", "value": 3
    } in matching[0]["count_evidence"]

    evidence_flags = [
        bool(c["count_evidence"]) for c in result["candidates"]
    ]
    assert evidence_flags == sorted(evidence_flags, reverse=True)


def test_three_unique_records_without_counter():
    data, start, expected = _three_record_sample(b"\xfe\xfe")
    result = infer_records(data)

    assert not _matching_three_record_candidates(
        result, start, expected
    )


def test_wrong_counter_does_not_support_three_records():
    data, start, expected = _three_record_sample(
        (9).to_bytes(2, "little")
    )
    result = infer_records(data)

    assert not _matching_three_record_candidates(
        result, start, expected
    )


def test_counter_evidence_is_limited_to_prefix():
    from src.unknown import _record_count_matches

    data = b"\x80\x90\x03\x00"
    assert _record_count_matches(data, start=2, count=3) == []
    assert {
        "start": 2, "end": 4, "encoding": "little", "value": 3
    } in _record_count_matches(data, start=4, count=3)
