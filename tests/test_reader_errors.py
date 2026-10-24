import json
import os
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "reader, expected_message",
    [
        ("demo.cfg1", "module:function"),
        (
            "_missing_diploma_reader_7f31:parse_file",
            "Cannot import reader module",
        ),
        (
            "builtins:_missing_diploma_function_7f31",
            "was not found",
        ),
        ("builtins:None", "is not callable"),
    ],
)
def test_joint_cli_saves_reader_configuration_error(
    tmp_path, reader, expected_message,
):
    samples = tmp_path / "samples"
    samples.mkdir()
    output = tmp_path / "report.json"
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "analyze_all.py"),
            "--samples", str(samples),
            "--reader", reader,
            "--limit", "5",
            "--out", str(output),
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )

    assert result.returncode == 1, result.stdout + result.stderr
    assert output.is_file(), result.stdout + result.stderr

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["run_status"] == "error"
    assert payload["reports"] == []
    assert payload["run_error"].startswith("ValueError:")
    assert expected_message in payload["run_error"]
    assert expected_message in result.stderr
    assert "Traceback (most recent call last)" not in result.stderr
