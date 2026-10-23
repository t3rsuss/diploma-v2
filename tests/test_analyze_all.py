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
