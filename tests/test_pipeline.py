import base64
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src import known
from src.pipeline import analyze_full
from src.segment import segment
from src.triage.triage import _fragment

PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)


def test_known_png_structure():
    d = known.describe(PNG, "png")
    assert d["fields_total"] >= 3
    assert d["coverage_top_level"] > 0.9


def test_pipeline_known_format(tmp_path):
    p = tmp_path / "x.png"
    p.write_bytes(PNG)
    rep = analyze_full(p)
    assert rep["branch"]
    assert "structure" in rep or "regions" in rep


def test_pipeline_unknown_bytes_gives_regions(tmp_path):
    p = tmp_path / "blob.bin"
    p.write_bytes(os.urandom(30000))
    rep = analyze_full(p)
    assert "regions" in rep
    assert rep["regions"][0]["start"] == 0
    assert rep["regions"][-1]["end"] == 30000


def test_segment_covers_all_bytes():
    data = b"2026-10-22 12:00:00 INFO service started\n" * 2000
    segs = segment(data, _fragment())
    assert segs[0]["start"] == 0
    assert segs[-1]["end"] == len(data)
    assert all(a["end"] == b["start"] for a, b in zip(segs, segs[1:]))