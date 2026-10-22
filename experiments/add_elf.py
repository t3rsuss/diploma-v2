import collections
import csv
import hashlib
import os
import pathlib
import random
import shutil
import struct

random.seed(44)

BASE = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = BASE / "results" / "corpus_manifest.csv"
OUT = BASE / "data" / "corpus" / "elf"
DESKTOP = pathlib.Path(r"C:\Users\vlad\Desktop")
SKIP = {".git", "node_modules", "__pycache__", "corpus", ".venv", "venv"}
PER = 40
MAXB = 5_000_000
NAMES = {3: "x86", 62: "x86-64", 40: "ARM", 183: "AArch64", 8: "MIPS",
         20: "PowerPC", 21: "PPC64", 42: "SuperH", 4: "m68k", 243: "RISC-V"}

with open(MANIFEST, encoding="utf-8", newline="") as fh:
    rows = list(csv.reader(fh))
header, old = rows[0], rows[1:]
seen = {r[1] for r in old}
need = PER - sum(1 for r in old if r[0] == "elf")
print("ELF у маніфесті:", PER - need, "потрібно додати:", need)

groups = collections.defaultdict(list)
by_folder = collections.Counter()
for dp, dn, fn in os.walk(DESKTOP, onerror=lambda e: None):
    dn[:] = [d for d in dn if d.lower() not in SKIP and not d.lower().startswith("mal")]
    parts = [x.lower() for x in pathlib.Path(dp).parts]
    if "samples" not in parts:
        continue
    for name in fn:
        p = pathlib.Path(dp) / name
        try:
            with open(p, "rb") as f:
                hd = f.read(20)
            size = p.stat().st_size
        except OSError:
            continue
        if len(hd) < 20 or hd[:4] != b"\x7fELF" or size < 512 or size > MAXB:
            continue
        m = struct.unpack("<H" if hd[5] == 1 else ">H", hd[18:20])[0]
        groups[m].append(p)
        by_folder[str(p.parent)] += 1

print("\nЗнайдено ELF за папками:")
for k, v in by_folder.most_common(15):
    print(f"  {v:5d}  {k}")
print("Знайдено за архітектурами:",
      {NAMES.get(m, m): len(v) for m, v in sorted(groups.items())})

for g in groups.values():
    random.shuffle(g)
picks = []
while len(picks) < need and any(groups.values()):
    for m in sorted(groups):
        if groups[m] and len(picks) < need:
            picks.append((m, groups[m].pop()))

OUT.mkdir(parents=True, exist_ok=True)
new_rows = []
for m, p in picks:
    b = p.read_bytes()
    h = hashlib.sha256(b).hexdigest()
    if h in seen:
        continue
    seen.add(h)
    dst = OUT / (h[:12] + ("." + p.suffix.lower().lstrip(".") if p.suffix else ""))
    shutil.copyfile(p, dst)
    new_rows.append(["elf", h, len(b), p.suffix.lower().lstrip("."), f"e_machine={m}", str(p)])

with open(MANIFEST, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(header)
    w.writerows(old)
    w.writerows(new_rows)

cnt = collections.Counter(r[4] for r in new_rows)
print("\nДодано ELF:", len(new_rows), dict(cnt))