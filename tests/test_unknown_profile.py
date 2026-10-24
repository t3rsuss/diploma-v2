import pytest

from src.unknown import analyze_unknown
from src import pipeline as P


def test_empty_observations():
    result = analyze_unknown(b"")
    assert result["size"] == 0
    assert result["profile"] == []
    assert result["numeric_candidates"] == []


@pytest.mark.parametrize(
    "data, expected",
    [
        (b"\x00" * 512, "zero_filled"),
        (b"A" * 512, "ascii_like"),
        (bytes(range(256)) * 4, "high_entropy"),
    ],
)
def test_profile_observations(data, expected):
    result = analyze_unknown(data)
    assert result["profile"][0]["observation"] == expected
    assert result["profile"][0]["start"] == 0
    assert result["profile"][-1]["end"] == len(data)
    assert all(
        left["end"] == right["start"]
        for left, right in zip(result["profile"], result["profile"][1:])
    )


def test_ascii_offsets_and_preview():
    result = analyze_unknown(b"\x00\x01hello world\x00")
    assert result["ascii_strings"] == [
        {"start": 2, "end": 13, "preview": "hello world",
         "preview_truncated": False}
    ]


def test_zero_runs():
    result = analyze_unknown(b"A" + b"\x00" * 10 + b"B")
    assert result["zero_runs"] == [{"start": 1, "end": 11}]


def test_numeric_size_relations():
    data = (100).to_bytes(4, "little")
    data += (92).to_bytes(4, "little") + b"A" * 92
    candidates = analyze_unknown(data)["numeric_candidates"]

    assert any(
        c["start"] == 0 and c["width"] == 4
        and c["value"] == 100 and c["relation"] == "matches_file_size"
        for c in candidates
    )
    assert any(
        c["start"] == 4 and c["width"] == 4
        and c["value"] == 92
        and c["relation"] == "matches_bytes_after_field"
        for c in candidates
    )


def test_observation_limits():
    result = analyze_unknown(
        (b"AAAA\x00BBBB\x00" * 1000), max_regions=3, max_items=1,
    )
    assert len(result["profile"]) <= 3
    assert len(result["ascii_strings"]) == 1
    assert result["ascii_strings_limited"] is True


def test_unknown_pipeline_adds_observations(tmp_path, monkeypatch):
    path = tmp_path / "sample.bin"
    data = b"\x00" * 16 + b"hello world"
    path.write_bytes(data)

    monkeypatch.setattr(
        P, "analyze",
        lambda path: {"format": "unknown", "confidence": 0.0},
    )
    monkeypatch.setattr(P.known, "available", lambda fmt: False)
    monkeypatch.setattr(P, "_fragment", lambda: None)
    monkeypatch.setattr(P, "segment", lambda data, model: [])

    report = P.analyze_full(path)
    assert report["format"] == "unknown"
    assert "structure" not in report
    assert report["unknown_analysis"]["size"] == len(data)
    assert report["unknown_analysis"]["zero_runs"] == [
        {"start": 0, "end": 16}
    ]
