import collections
import csv
import pathlib
import sys

BASE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from src.triage.triage import analyze

with open(BASE / "results" / "govdocs_test.csv", encoding="utf-8", newline="") as fh:
    rows = [r for r in csv.DictReader(fh) if r["format"] in ("txt", "xml", "log")]
for cls in ("txt", "xml", "log"):
    reps = [analyze(r["src"], run_v1=False) for r in rows if r["format"] == cls]
    print(f"\n{cls}: файлів {len(reps)}")
    print("  Magika:", collections.Counter(
        f"{x['magika']['label']}({x['magika']['score']:.1f})" for x in reps).most_common(10))
    print("  система:", collections.Counter(
        f"{x['format']}/{x['format_source'][:6]}" for x in reps).most_common(8))
    print("  модель фрагментів:", collections.Counter(
        x["fragment_model"]["class"] for x in reps).most_common(6))