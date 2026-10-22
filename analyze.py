import argparse
import json
import pathlib
import sys

BASE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))
from src.pipeline import analyze_full

ap = argparse.ArgumentParser(description="Сортувальник бінарних файлів: формат, гілка аналізу, структура")
ap.add_argument("path")
ap.add_argument("--regions", action="store_true", help="примусово побудувати карту областей")
ap.add_argument("--json", action="store_true")
a = ap.parse_args()

rep = analyze_full(a.path, force_regions=a.regions)
if a.json:
    print(json.dumps(rep, ensure_ascii=False, indent=2, default=float))
    sys.exit(0)

print(f"{rep['file']}: {rep['size']} Б")
print(f"Формат: {rep['format']} (джерело: {rep['format_source']}, впевненість {rep['confidence']})")
print(f"Гілка: {rep['branch']}")
for f in rep["flags"]:
    print(f"  позначка: {f}")
if "executable_analysis" in rep:
    ea = rep["executable_analysis"]
    print("Виконуваний файл:", {k: ea[k] for k in ea if k in ("kind", "level", "score", "error", "reasons")})
if "structure" in rep:
    st = rep["structure"]
    print(f"Парсер {st['parser']}: полів верхнього рівня {st['fields_total']}, покриття {100 * st['coverage_top_level']:.1f} %")
    print(f"{'поле':28s}{'початок':>10s}{'кінець':>10s}  тип")
    for f in st["fields"]:
        print(f"{f['name']:28s}{f['start']:10d}{f['end']:10d}  {f['type']}")
if "structure_error" in rep:
    print("Помилка опису Kaitai:", rep["structure_error"])
if "regions" in rep:
    print(f"{'зсув':>12s}{'довжина':>12s}  {'клас':8s}{'впевненість':>12s}")
    for s in rep["regions"]:
        print(f"{s['start']:#12x}{s['length']:12d}  {s['cls']:8s}{s['conf']:12.2f}")