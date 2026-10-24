from types import SimpleNamespace

import pytest

from src.triage import triage as T
from src import pipeline as P


def install_models(monkeypatch, label, score, candidate="jpg", candidate_score=0.99):
    result = SimpleNamespace(
        ok=label != "error",
        output=SimpleNamespace(label=label),
        score=score,
    )
    magika = SimpleNamespace(identify_bytes=lambda data: result)
    fragment = SimpleNamespace(
        classify=lambda data: (
            candidate, candidate_score, {candidate: candidate_score}
        )
    )
    monkeypatch.setattr(T, "_magika", lambda: magika)
    monkeypatch.setattr(T, "_fragment", lambda: fragment)
    return fragment


@pytest.mark.parametrize(
    "label, score, expected",
    [
        ("unknown", 0.99, "unknown"),
        ("png", 0.4, "unknown"),
        ("png", 0.95, "png"),
        ("txt", 0.95, "txt"),
        ("error", 0.0, "unknown"),
    ],
)
def test_single_file_format_decision(tmp_path, monkeypatch, label, score, expected):
    install_models(monkeypatch, label, score)
    path = tmp_path / "sample.bin"
    path.write_bytes(b"\x13\x37" * 256)

    report = T.analyze(path, run_v1=False)

    assert report["format"] == expected
    assert report["format_status"] == (
        "unrecognized" if expected == "unknown" else "recognized"
    )
    if expected == "unknown":
        assert report["format_candidate"]["format"] == "jpg"
        assert report["confidence_kind"] == "not_applicable"
    else:
        assert report["format_candidate"] is None


def test_high_fragment_score_is_not_format_confirmation(tmp_path, monkeypatch):
    install_models(monkeypatch, "unknown", 0.99, "pdf", 0.999)
    path = tmp_path / "sample.bin"
    path.write_bytes(b"\x13\x37" * 256)

    report = T.analyze(path, run_v1=False)

    assert report["format"] == "unknown"
    assert report["format_candidate"]["format"] == "pdf"
    assert report["format_candidate"]["score"] == 0.999


def test_extension_does_not_establish_format(tmp_path, monkeypatch):
    install_models(monkeypatch, "unknown", 0.99)
    path = tmp_path / "sample.png"
    path.write_bytes(b"\x13\x37" * 256)

    report = T.analyze(path, run_v1=False)

    assert report["extension_class"] == "png"
    assert report["format"] == "unknown"
    assert not any("не відповідає визначеному формату" in f for f in report["flags"])


def test_unknown_file_uses_regions_not_candidate_parser(tmp_path, monkeypatch):
    fragment = install_models(monkeypatch, "unknown", 0.99, "png", 0.999)
    monkeypatch.setattr(P, "_fragment", lambda: fragment)
    monkeypatch.setattr(P.known, "available", lambda fmt: fmt == "png")

    def forbidden_parser(*args, **kwargs):
        raise AssertionError("A candidate must not select a known-format parser")

    monkeypatch.setattr(P.known, "describe", forbidden_parser)
    monkeypatch.setattr(
        P, "segment",
        lambda data, model: [
            {"start": 0, "end": len(data), "length": len(data),
             "cls": "png", "conf": 0.999}
        ],
    )
    path = tmp_path / "sample.bin"
    path.write_bytes(b"\x13\x37" * 256)

    report = P.analyze_full(path)

    assert report["format"] == "unknown"
    assert "structure" not in report
    assert report["regions"][0]["end"] == path.stat().st_size
    assert report["branch"].startswith("невідомий формат")
