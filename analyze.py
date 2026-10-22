import argparse
import json
import pathlib
import sys

BASE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))
from src.segment import BONUS, LAM, segment
from src.triage.fragment import FragmentClassifier

ap = argparse.ArgumentParser(description="Карта ділянок бінарного образу за типами даних")
ap.add_argument("path")
ap.add_argument("--lam", type=float, default=LAM, help="штраф за зміну класу")
ap.add_argument("--bonus", type=float, default=BONUS, help="бонус за сигнатуру")
ap.add_argument("--no-snap", action="store_true", help="не уточнювати межі за сигнатурами")
ap.add_argument("--json", action="store_true")
a = ap.parse_args()

data = pathlib.Path(a.path).read_bytes()
if len(data) > 256 * 2**20:
    print("Увага: файл понад 256 МБ, обробка буде довгою", file=sys.stderr)
segs = segment(data, FragmentClassifier(), a.lam, a.bonus, snap=not a.no_snap)
if a.json:
    print(json.dumps(segs, ensure_ascii=False, indent=2))
else:
    print(f"{a.path}: {len(data)} Б, ділянок {len(segs)}")
    print(f"{'зсув':>12s}{'довжина':>12s}  {'клас':8s}{'впевненість':>12s}")
    for s in segs:
        print(f"{s['start']:#12x}{s['length']:12d}  {s['cls']:8s}{s['conf']:12.2f}")