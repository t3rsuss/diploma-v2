from recovery_audit import audit_intervals


def test_full_coverage():
    result = audit_intervals([(0, 4), (4, 10)], 10)
    assert result["covered_bytes"] == 10
    assert result["coverage"] == 1.0
    assert result["overlap_bytes"] == 0
    assert result["uncovered_intervals"] == []


def test_gap():
    result = audit_intervals([(0, 3), (5, 10)], 10)
    assert result["covered_bytes"] == 8
    assert result["uncovered_intervals"] == [{"start": 3, "end": 5}]


def test_overlap():
    result = audit_intervals([(0, 7), (4, 10)], 10)
    assert result["covered_bytes"] == 10
    assert result["overlap_bytes"] == 3
    assert result["overlap_intervals"] == [{"start": 4, "end": 7}]


def test_duplicate():
    result = audit_intervals([(0, 10), (0, 10)], 10)
    assert result["covered_bytes"] == 10
    assert result["overlap_bytes"] == 10


def test_invalid_intervals():
    result = audit_intervals([(-1, 3), (2, 11), (4, 4)], 10)
    assert len(result["invalid_intervals"]) == 3
    assert result["covered_bytes"] == 0


def test_empty_file():
    result = audit_intervals([], 0)
    assert result["covered_bytes"] == 0
    assert result["uncovered_intervals"] == []
