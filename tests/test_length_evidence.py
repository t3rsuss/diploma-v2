import pathlib

import analyze_all as A
from demo import cfg1
from length_evidence import explain_lengths


def prepare(tmp_path, monkeypatch):
    monkeypatch.setattr(cfg1, "OUT", tmp_path / "samples")
    monkeypatch.setattr(cfg1, "LABELS", tmp_path / "labels.json")
    folder, _ = cfg1.generate(n_benign=8, n_mal=0)
    return folder


def used_samples(audit):
    paths = [
        pathlib.Path(entry["path"])
        for entry in audit
        if entry["stage"] == "inference" and entry["status"] == "used"
    ]
    samples = []
    for path in paths:
        data = path.read_bytes()
        log = A.RB._trace_custom(cfg1.parse_file, data)
        samples.append((data, log))
    return paths, samples


def test_joint_evidence_does_not_change_fields(tmp_path, monkeypatch):
    folder = prepare(tmp_path, monkeypatch)
    audit = []
    reports = A.analyze_set(
        [str(folder)], reader="demo.cfg1:parse_file",
        limit=5, sample_audit=audit,
    )
    paths, samples = used_samples(audit)
    expected = A.RB.INF2.infer2(samples)
    indexed = {r["path"]: r for r in reports if r["status"] == "ok"}

    assert len(paths) == len(indexed) == 5
    for path, fields in zip(paths, expected):
        actual = [
            (f["start"], f["end"], f["role"])
            for f in indexed[str(path)]["fields"]
        ]
        assert actual == fields


def test_joint_evidence_uses_actual_limited_sample_set(tmp_path, monkeypatch):
    folder = prepare(tmp_path, monkeypatch)
    audit = []
    reports = A.analyze_set(
        [str(folder)], reader="demo.cfg1:parse_file",
        limit=5, sample_audit=audit,
    )
    paths, samples = used_samples(audit)
    expected = explain_lengths(samples)
    indexed = {r["path"]: r for r in reports if r["status"] == "ok"}

    assert len(paths) == 5
    assert any(expected)
    for path, evidence in zip(paths, expected):
        actual = indexed[str(path)]["length_evidence"]
        assert actual == evidence
        assert all(e["files_with_matching_events"] <= 5 for e in actual)
