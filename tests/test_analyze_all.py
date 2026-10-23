from analyze_all import analyze_set
from demo import cfg1


def test_cfg1_targets_are_ranked(tmp_path, monkeypatch):
    monkeypatch.setattr(cfg1, "OUT", tmp_path / "samples")
    monkeypatch.setattr(cfg1, "LABELS", tmp_path / "labels.json")
    folder, labels = cfg1.generate()

    indicator = next(
        n for n, label in labels.items()
        if label["malicious"] and label["kind"] in ("pe", "xor_pe")
    )
    baseline = next(
        n for n, label in labels.items()
        if not label["malicious"] and label["kind"] == "benign"
    )
    reports = analyze_set(
        [str(folder)],
        [str(folder / indicator), str(folder / baseline)],
        reader="demo.cfg1:parse_file",
    )
    indexed = {r["file"]: r for r in reports}
    assert len(indexed) == 2
    assert indexed[indicator]["risk"] == "високий"
    assert indexed[baseline]["risk"] in (
        "індикаторів не виявлено", "інформаційний"
    )
    assert all(r["status"] == "ok" for r in reports)

def test_read_block_entropy_is_informational():
    from analyze_all import block_rank
    assert block_rank({
        "kind": "блок з високою ентропією",
        "severity": "середній",
    }) == 1


def test_pe_indicator_keeps_high_priority():
    from analyze_all import block_rank
    assert block_rank({
        "kind": "вбудований PE-файл",
        "severity": "високий",
    }) == 3

def test_truncated_target_is_reported_as_error(tmp_path, monkeypatch):
    monkeypatch.setattr(cfg1, "OUT", tmp_path / "samples")
    monkeypatch.setattr(cfg1, "LABELS", tmp_path / "labels.json")
    folder, labels = cfg1.generate()

    source = folder / next(iter(labels))
    damaged = tmp_path / "truncated.cfg"
    damaged.write_bytes(source.read_bytes()[:16])

    reports = analyze_set(
        [str(folder)], [str(damaged)],
        reader="demo.cfg1:parse_file",
    )

    assert len(reports) == 1
    assert reports[0]["status"] == "error"
    assert reports[0]["risk"] == "не оцінено"
    assert reports[0]["error"]

def test_oversized_target_is_not_read(tmp_path, monkeypatch):
    import pathlib

    monkeypatch.setattr(cfg1, "OUT", tmp_path / "samples")
    monkeypatch.setattr(cfg1, "LABELS", tmp_path / "labels.json")
    folder, _ = cfg1.generate()

    oversized = tmp_path / "oversized.cfg"
    oversized.write_bytes(b"A" * 300001)

    original = pathlib.Path.read_bytes

    def guarded_read(path):
        if path.resolve() == oversized.resolve():
            raise AssertionError("Oversized target was read")
        return original(path)

    monkeypatch.setattr(pathlib.Path, "read_bytes", guarded_read)

    reports = analyze_set(
        [str(folder)], [str(oversized)],
        reader="demo.cfg1:parse_file",
    )
    assert len(reports) == 1
    assert reports[0]["status"] == "error"
    assert reports[0]["risk"] == "не оцінено"
    assert "Supported file size" in reports[0]["error"]


def test_missing_target_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(cfg1, "OUT", tmp_path / "samples")
    monkeypatch.setattr(cfg1, "LABELS", tmp_path / "labels.json")
    folder, _ = cfg1.generate()

    reports = analyze_set(
        [str(folder)], [str(tmp_path / "missing.cfg")],
        reader="demo.cfg1:parse_file",
    )
    assert len(reports) == 1
    assert reports[0]["status"] == "error"
    assert "FileNotFoundError" in reports[0]["error"]
