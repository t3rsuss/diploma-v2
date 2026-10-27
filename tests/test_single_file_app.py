import hashlib
import pathlib

import pytest
from streamlit.testing.v1 import AppTest

from views import single_file as UI

ROOT = pathlib.Path(__file__).resolve().parents[1]


def sample_report(fmt="unknown"):
    return {
        "file": "sample.bin",
        "size": 512,
        "sha256": "a" * 64,
        "format": fmt,
        "format_source": "test source",
        "format_status": (
            "unrecognized" if fmt == "unknown" else "recognized"
        ),
        "branch": "test branch",
        "flags": [],
        "regions": [
            {"start": 0, "end": 512, "length": 512,
             "cls": "png", "conf": 0.999}
        ],
    }


def test_single_file_page_opens():
    page = AppTest.from_file(str(ROOT / "views" / "single_file.py")).run()
    assert not page.exception
    assert page.title[0].value == "Аналіз бінарних даних"
    assert any(b.label == "Проаналізувати" for b in page.button)


@pytest.mark.parametrize("data", [b"", b"A" * 9])
def test_upload_validation(monkeypatch, data):
    monkeypatch.setattr(UI, "MAX_UPLOAD_BYTES", 8)

    def forbidden(*args, **kwargs):
        raise AssertionError("Invalid upload must not reach the pipeline")

    monkeypatch.setattr(UI, "analyze_full", forbidden)
    with pytest.raises(ValueError):
        UI.analyze_upload(data, "sample.bin")


def test_upload_preserves_identity_and_cleans_temp_file(monkeypatch):
    paths = []

    def fake_pipeline(path):
        paths.append(pathlib.Path(path))
        assert pathlib.Path(path).read_bytes() == b"test-data"
        assert pathlib.Path(path).suffix == ".bin"
        return sample_report()

    monkeypatch.setattr(UI, "analyze_full", fake_pipeline)
    report = UI.analyze_upload(b"test-data", "original.bin")

    assert report["file"] == "original.bin"
    assert report["size"] == 9
    assert report["sha256"] == hashlib.sha256(b"test-data").hexdigest()
    assert report["analysis_scope"] == "single_file"
    assert not paths[0].exists()


@pytest.mark.parametrize("fmt", ["unknown", "png"])
def test_single_file_result_display(fmt):
    page = AppTest.from_file(str(ROOT / "views" / "single_file.py"))
    page.session_state[UI.REPORT_KEY] = sample_report(fmt)
    page.run()

    assert not page.exception
    assert len(page.dataframe) == 1
    assert page.dataframe[0].value["припущення про вміст"].tolist() == ["png"]
    assert len(page.get("download_button")) == 1

    if fmt == "unknown":
        assert any(w.value == "Формат не встановлено" for w in page.warning)
    else:
        assert any(i.value == "Визначений тип: PNG" for i in page.info)


def test_empty_submission_clears_previous_result():
    page = AppTest.from_file(str(ROOT / "views" / "single_file.py"))
    page.session_state[UI.REPORT_KEY] = sample_report()
    page.run()

    button = next(b for b in page.button if b.label == "Проаналізувати")
    button.click().run()

    assert not page.exception
    assert any(e.value == "Спочатку виберіть файл." for e in page.error)
    assert len(page.get("download_button")) == 0
    assert len(page.dataframe) == 0
