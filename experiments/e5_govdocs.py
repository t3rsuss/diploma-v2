import collections
import csv
import pathlib
import sys

BASE = pathlib.Path(r"C:\Users\vlad\Desktop\diploma-v2")
sys.path.insert(0, str(BASE))
from src.triage.triage import THETA, TEXT_FAMILY, analyze

SRC = BASE / "results" / "govdocs_test.csv"
MIN_N = 10

with open(SRC, encoding="utf-8", newline="") as fh:
    rows = list(csv.DictReader(fh))
res = []
for i, r in enumerate(rows):
    try:
        res.append((r["format"], analyze(r["src"], run_v1=False)))
    except Exception:
        pass
    if (i + 1) % 100 == 0:
        print(f"{i + 1}/{len(rows)}", flush=True)


def same(cls, pred):
    if pred == cls:
        return True
    return cls == "log" and pred == "txt"


by = collections.defaultdict(list)
for cls, rep in res:
    by[cls].append(rep)

print(f"\nФайлів оброблено: {len(res)} з {len(rows)}")
print(f"{'клас':7s}{'n':>5s}{'Magika':>8s}{'охопл.':>8s}{'точн.':>7s}{'фрагм.':>8s}{'система':>9s}{'родина':>8s}")
mac = collections.defaultdict(list)
for cls in sorted(c for c in by if c != "other"):
    reps = by[cls]
    n = len(reps)
    m_all = sum(same(cls, x["magika"]["class"]) for x in reps) / n
    ans = [x for x in reps if x["magika"]["class"] and x["magika"]["score"] >= THETA]
    cov = len(ans) / n
    acc = sum(same(cls, x["magika"]["class"]) for x in ans) / len(ans) if ans else 0.0
    fr = sum(same(cls, x["fragment_model"]["class"]) for x in reps) / n
    sy = sum(same(cls, x["format"]) for x in reps) / n
    fam = sum((x["format"] in TEXT_FAMILY) if cls in TEXT_FAMILY else same(cls, x["format"])
              for x in reps) / n
    star = "*" if n < MIN_N else " "
    print(f"{cls:7s}{n:4d}{star}{100 * m_all:8.1f}{100 * cov:8.1f}{100 * acc:7.1f}"
          f"{100 * fr:8.1f}{100 * sy:9.1f}{100 * fam:8.1f}")
    if n >= MIN_N:
        for k, v in (("m", m_all), ("c", cov), ("a", acc), ("f", fr), ("s", sy), ("r", fam)):
            mac[k].append(v)
print(f"\nМакро за класами з n >= {MIN_N} ({len(mac['m'])} класів):")
print(f"  Magika {100 * sum(mac['m']) / len(mac['m']):.1f} %, охоплення {100 * sum(mac['c']) / len(mac['c']):.1f} %, "
      f"точність серед відповідей {100 * sum(mac['a']) / len(mac['a']):.1f} %")
print(f"  модель фрагментів {100 * sum(mac['f']) / len(mac['f']):.1f} %, "
      f"система {100 * sum(mac['s']) / len(mac['s']):.1f} %, "
      f"система з текстовою родиною {100 * sum(mac['r']) / len(mac['r']):.1f} %")

oth = by.get("other", [])
if oth:
    print(f"\nКлас other ({len(oth)} файлів): що відповідає система")
    print("  формат:", collections.Counter(x["format"] for x in oth).most_common(6))
    print("  джерело:", collections.Counter(x["format_source"] for x in oth).most_common(3))
    print("  Magika:", collections.Counter(x["magika"]["label"] for x in oth).most_common(6))
    low = sum(x["confidence"] < 0.5 for x in oth) / len(oth)
    print(f"  частка з впевненістю < 0.5: {100 * low:.1f} %")