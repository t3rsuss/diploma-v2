"""Підготовка окремого набору демонстраційних даних."""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import analyze_all
from demo import cfg1, xdt3


def main():
    destination = ROOT / "data" / "demo_ready"
    if destination.exists():
        raise SystemExit(
            "data/demo_ready already exists. Nothing overwritten."
        )

    destination.mkdir(parents=True)

    old_xdt_out = xdt3.OUT
    old_cfg_out = cfg1.OUT
    old_labels = cfg1.LABELS

    try:
        xdt3.OUT = destination / "xdt3"
        cfg1.OUT = destination / "cfg1"
        cfg1.LABELS = destination / "cfg1_labels.json"

        xdt3.generate(n=20, seed=20261024)
        cfg1.generate(n_benign=20, n_mal=20, seed=20261025)
    finally:
        xdt3.OUT = old_xdt_out
        cfg1.OUT = old_cfg_out
        cfg1.LABELS = old_labels

    counts = {
        "xdt3": len(list((destination / "xdt3").glob("*.xd3"))),
        "cfg1": len(list((destination / "cfg1").glob("*.cfg"))),
    }
    if counts != {"xdt3": 20, "cfg1": 40}:
        raise RuntimeError(f"Unexpected sample counts: {counts}")

    manifest = {
        "purpose": "Reproducible synthetic demonstration; not an independent test.",
        "datasets": {
            "xdt3": {"files": counts["xdt3"], "seed": 20261024},
            "cfg1": {"files": counts["cfg1"], "seed": 20261025},
        },
    }
    (destination / "demo_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    for name, count in counts.items():
        print(f"{name}: {count} files")
    print("Prepared: data/demo_ready")
    print("Existing demo samples and historical results were not overwritten.")


if __name__ == "__main__":
    main()
