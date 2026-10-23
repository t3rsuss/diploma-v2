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


def test_collection_audits_rejected_files(tmp_path):
    from analyze_all import collect_with_audit

    valid = tmp_path / "valid.bin"
    valid.write_bytes(b"A" * 16)
    small = tmp_path / "small.bin"
    small.write_bytes(b"A")
    missing = tmp_path / "missing.bin"
    audit = []

    selected = collect_with_audit(
        [str(valid), str(small), str(missing)], 10, audit,
    )

    assert selected == [valid]
    indexed = {entry["file"]: entry for entry in audit}
    assert indexed["valid.bin"]["status"] == "selected"
    assert indexed["small.bin"]["status"] == "rejected"
    assert "Supported file size" in indexed["small.bin"]["reason"]
    assert "FileNotFoundError" in indexed["missing.bin"]["reason"]


def test_collection_audits_candidate_limit(tmp_path):
    from analyze_all import collect_with_audit

    for i in range(4):
        (tmp_path / f"{i}.bin").write_bytes(b"A" * 16)

    audit = []
    selected = collect_with_audit([str(tmp_path)], 2, audit)

    assert len(selected) == 2
    skipped = [
        entry for entry in audit
        if entry.get("reason") == "candidate_limit"
    ]
    assert len(skipped) == 2


def test_sample_audit_survives_target_filter(tmp_path, monkeypatch):
    monkeypatch.setattr(cfg1, "OUT", tmp_path / "samples")
    monkeypatch.setattr(cfg1, "LABELS", tmp_path / "labels.json")
    folder, labels = cfg1.generate()

    target = folder / next(iter(labels))
    rejected = folder / "too_small.cfg"
    rejected.write_bytes(b"A")
    audit = []

    reports = analyze_set(
        [str(folder)], [str(target)],
        reader="demo.cfg1:parse_file",
        sample_audit=audit,
    )

    assert len(reports) == 1
    assert reports[0]["file"] == target.name
    assert any(
        entry["file"] == rejected.name
        and entry["status"] == "rejected"
        for entry in audit
    )
    assert any(
        entry["file"] != target.name
        and entry["stage"] == "inference"
        and entry["status"] == "used"
        for entry in audit
    )


def test_cli_saves_audit_when_readable_samples_are_insufficient(
    tmp_path, monkeypatch,
):
    import json
    import sys
    import pytest
    import analyze_all as cli

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"A" * 16)
    output = tmp_path / "results" / "failed_analysis.json"

    monkeypatch.setattr(
        cli.RB.CTX, "run_ctx",
        lambda fmt, data: [],
    )
    monkeypatch.setattr(sys, "argv", [
        "analyze_all.py",
        "--samples", str(sample),
        "--format", "png",
        "--out", str(output),
    ])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 1
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 2
    assert payload["run_status"] == "error"
    assert "Need at least 5 readable files" in payload["run_error"]
    assert payload["reports"] == []
    assert any(
        entry["file"] == sample.name
        and entry["stage"] == "reading"
        and entry["status"] == "rejected"
        and "Reader produced no read events" in entry["reason"]
        for entry in payload["sample_audit"]
    )


def test_joint_report_contains_field_details(tmp_path, monkeypatch):
    monkeypatch.setattr(cfg1, "OUT", tmp_path / "samples")
    monkeypatch.setattr(cfg1, "LABELS", tmp_path / "labels.json")
    folder, labels = cfg1.generate()
    target = folder / next(iter(labels))

    reports = analyze_set(
        [str(folder)], [str(target)],
        reader="demo.cfg1:parse_file",
    )

    assert len(reports) == 1
    report = reports[0]
    assert report["status"] == "ok"
    assert report["fields"]

    data = target.read_bytes()
    for field in report["fields"]:
        a, b = field["start"], field["end"]
        assert field["size"] == b - a
        assert isinstance(field["context"], str)
        assert field["context"]
        assert field["hex"] == data[a:min(b, a + 8)].hex()
        assert len(field["hex"]) <= 16


def test_inference_count_mismatch_is_not_silent(tmp_path, monkeypatch):
    import pytest
    import analyze_all as cli

    monkeypatch.setattr(cfg1, "OUT", tmp_path / "samples")
    monkeypatch.setattr(cfg1, "LABELS", tmp_path / "labels.json")
    folder, _ = cfg1.generate(n_benign=5, n_mal=0)
    monkeypatch.setattr(cli.RB.INF2, "infer2", lambda samples: [])

    audit = []
    with pytest.raises(ValueError, match="Inference result count mismatch"):
        analyze_set(
            [str(folder)],
            reader="demo.cfg1:parse_file",
            sample_audit=audit,
        )

    assert not any(
        entry["stage"] == "inference" and entry["status"] == "used"
        for entry in audit
    )
