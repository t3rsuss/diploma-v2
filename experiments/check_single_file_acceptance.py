import hashlib
import io
import json
import pathlib
import platform
import random
import subprocess
import sys
import wave

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import rebin
from views.single_file import MAX_UPLOAD_BYTES, analyze_upload
from demo import cfg1


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def cfg1_exact_rank(report, data):
    truth = cfg1.truth_fields(data)
    count = int.from_bytes(data[5:7], "little")
    require(
        count >= 1 and len(truth) == 4 + 3 * count,
        "Invalid CFG1 reference layout.",
    )

    expected = [
        (
            truth[i][0], truth[i][1],
            truth[i + 2][0], truth[i + 2][1],
        )
        for i in range(4, len(truth), 3)
    ]
    search = report.get("unknown_analysis", {}).get(
        "record_hypotheses", {}
    )

    for rank, candidate in enumerate(search.get("candidates", []), 1):
        spans = [
            (
                rec["start"], rec["type_end"],
                rec["payload_start"], rec["end"],
            )
            for rec in candidate["records"]
        ]
        if (
            candidate["type_width"] == 1
            and candidate["length_width"] == 2
            and candidate["byte_order"] == "little"
            and spans == expected
        ):
            return rank
    return None


def main():
    cfg_files = sorted((ROOT / "data/demo_ready/cfg1").glob("*.cfg"))
    require(bool(cfg_files), "CFG1 samples not found.")
    cfg_source = cfg_files[0]

    python_source = pathlib.Path(sys.executable)
    python_data = python_source.read_bytes()
    require(
        python_data[:2] == b"MZ",
        "This acceptance scenario requires a Windows Python executable.",
    )
    require(
        len(python_data) <= MAX_UPLOAD_BYTES,
        "Python executable exceeds the upload limit.",
    )

    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as audio:
        audio.setnchannels(1)
        audio.setsampwidth(2)
        audio.setframerate(8000)
        audio.writeframes(b"\x00\x00" * 800)

    cases = [
        ("wav", "generated.wav", buffer.getvalue()),
        ("text", "plain_text.txt", b"service=node\ncache=enabled\n" * 100),
        ("random", "random.bin", random.Random(731).randbytes(2048)),
        ("cfg1", "unknown_cfg1.bin", cfg_source.read_bytes()),
        ("pe", "python.exe", python_data),
        ("disguised_pe", "python_disguised.txt", python_data),
    ]

    results = []

    for kind, name, data in cases:
        report = None
        row = {
            "case": kind,
            "file": name,
            "input_bytes": len(data),
            "input_sha256": hashlib.sha256(data).hexdigest(),
            "passed": False,
        }

        try:
            report = analyze_upload(data, name)

            require(report.get("file") == name, "Incorrect output filename.")
            require(report.get("size") == len(data), "Incorrect output size.")
            require(
                report.get("sha256") == row["input_sha256"],
                "Incorrect input hash.",
            )
            require(
                report.get("analysis_scope") == "single_file",
                "Incorrect analysis scope.",
            )

            if kind == "wav":
                require(report.get("format") == "wav", "WAV not recognized.")
                require(bool(report.get("structure")), "WAV structure missing.")
                require(
                    not report.get("structure_error"),
                    "WAV parser returned an error.",
                )

            elif kind == "text":
                require(
                    report.get("format") in ("ini", "txt", "log"),
                    "Text-family format not recognized.",
                )
                require(
                    not report.get("executable_analysis"),
                    "Text routed to executable analysis.",
                )

            elif kind in ("random", "cfg1"):
                require(
                    report.get("format") == "unknown",
                    "Expected unknown format.",
                )
                observations = report.get("unknown_analysis")
                require(bool(observations), "Unknown analysis missing.")
                search = observations.get("record_hypotheses")
                require(bool(search), "Record-search result missing.")
                require(
                    not search.get("search_truncated"),
                    "Record search unexpectedly truncated on this fixture.",
                )

                if kind == "cfg1":
                    row["exact_cfg1_rank"] = cfg1_exact_rank(report, data)
                    require(
                        row["exact_cfg1_rank"] == 1,
                        "CFG1 reference hypothesis is not first.",
                    )

            else:
                require(report.get("format") == "pe", "PE not recognized.")
                require(
                    report.get("branch") == "виконуваний файл",
                    "Incorrect executable branch.",
                )
                executable = report.get("executable_analysis")
                require(bool(executable), "Executable analysis missing.")
                require(
                    not executable.get("error"),
                    "Executable analysis failed: "
                    + str(executable.get("error")),
                )
                require(
                    executable.get("level") in ("low", "mid", "high"),
                    "Executable risk level missing or invalid.",
                )

                if kind == "disguised_pe":
                    require(
                        any(
                            "виконуваний файл (pe)" in flag
                            and ".txt" in flag
                            for flag in report.get("flags", [])
                        ),
                        "Disguised-extension warning missing.",
                    )

            row["passed"] = True

        except Exception as exc:
            row["error"] = f"{type(exc).__name__}: {exc}"

        if report is not None:
            search = (
                report.get("unknown_analysis", {})
                .get("record_hypotheses", {})
            )
            row.update({
                "format": report.get("format"),
                "branch": report.get("branch"),
                "record_candidates": len(search.get("candidates", [])),
                "flags": report.get("flags", []),
            })

        results.append({"summary": row, "report": report})
        print(json.dumps(row, ensure_ascii=False, indent=2), flush=True)

    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    source_paths = [
        "app.py",
        "views/single_file.py",
        "src/pipeline.py",
        "src/unknown.py",
        "src/triage/triage.py",
        "experiments/check_single_file_acceptance.py",
    ]
    source_hashes = {
        path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
        for path in source_paths
    }

    passed = sum(item["summary"]["passed"] for item in results)
    output = ROOT / "results/single_file_acceptance.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps({
            "scope": (
                "Regression acceptance check for six established single-file "
                "fixtures. Not an independent accuracy evaluation, an ELF "
                "check, a UI check, or a threat-detector benchmark."
            ),
            "commit": commit,
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "source_hashes": source_hashes,
            "cfg1_source": str(cfg_source.relative_to(ROOT)),
            "python_executable_sha256": hashlib.sha256(
                python_data
            ).hexdigest(),
            "summary": {"passed": passed, "total": len(results)},
            "cases": results,
        }, ensure_ascii=False, indent=2, default=float),
        encoding="utf-8",
    )

    print("Saved:", output)
    print(f"PASS: {passed}/{len(results)}")

    if passed != len(results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
