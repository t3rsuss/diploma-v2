"""Verify locally tested pretrained models; optionally download upstream models."""
import argparse
import hashlib
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def problems(rows, folder):
    errors = []
    for row in rows:
        path = folder / row["name"]
        if not path.is_file():
            errors.append(row["name"] + ": missing")
            continue
        raw = path.read_bytes()
        if len(raw) != row["bytes"]:
            errors.append(row["name"] + ": size mismatch")
        elif hashlib.sha256(raw).hexdigest() != row["sha256"]:
            errors.append(row["name"] + ": SHA-256 mismatch")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--download", action="store_true",
        help="Allow the upstream downloader to retrieve its model bundle.",
    )
    args = parser.parse_args()

    manifest = json.loads(
        (ROOT / "docs/pretrained_models_manifest.json").read_text(
            encoding="utf-8"
        )
    )
    rows = manifest["files"]
    folder = ROOT / "data/ember_models"
    errors = problems(rows, folder)

    if errors and args.download:
        existing_mismatches = [
            error for error in errors if not error.endswith(": missing")
        ]
        if existing_mismatches:
            raise SystemExit(
                "Existing files differ; refusing automatic replacement:\n"
                + "\n".join(existing_mismatches)
            )

        folder.mkdir(parents=True, exist_ok=True)
        import thrember
        print("Downloading upstream bundle; this can include all 14 models.")
        thrember.download_models(str(folder))
        errors = problems(rows, folder)

    if errors:
        raise SystemExit(
            "Model verification failed:\n"
            + "\n".join(errors)
            + "\nUse --download only if you want to download the upstream bundle."
        )

    for row in rows:
        print("OK:", row["name"], row["bytes"], row["sha256"])
    print("Verified required models:", len(rows))


if __name__ == "__main__":
    main()
