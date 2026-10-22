import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo.make_xdt_samples import main as generate
from rebin import analyze, show


def main():
    generate()

    samples = ROOT / "demo" / "samples_xdt1"
    output = ROOT / "results" / "rebin_xdt1.json"

    report = analyze(
        [str(samples)],
        reader="demo.xdt_reader:parse_file",
        limit=20,
    )

    if report["files"] != 20:
        raise RuntimeError(
            f"Expected 20 analyzed files, got {report['files']}"
        )

    example = samples / report["example_file"]
    size = example.stat().st_size
    fields = report["example_fields"]

    if not fields:
        raise RuntimeError("No inferred fields")

    cursor = 0
    for field in sorted(fields, key=lambda f: (f["start"], f["end"])):
        start, end = field["start"], field["end"]

        if not 0 <= start < end <= size:
            raise RuntimeError(f"Invalid interval: {start}..{end}")

        if start != cursor:
            raise RuntimeError(
                f"Gap or overlap: expected start {cursor}, got {start}"
            )

        cursor = end

    if cursor != size:
        raise RuntimeError(
            f"Uncovered file tail: {cursor}..{size}"
        )

    report["reader"] = "xdt1"
    report["smoke_test"] = {
        "analyzed_files": report["files"],
        "example_size": size,
        "example_intervals_contiguous": True,
        "note": (
            "Checks execution and interval consistency for one example; "
            "does not measure semantic accuracy."
        ),
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    show(report)
    print(f"\nPASS: 20 files analyzed; example covers {size} bytes")
    print(f"Saved: {output}")


if __name__ == "__main__":
    main()
