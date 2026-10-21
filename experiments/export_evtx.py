import collections
import csv
import hashlib
import pathlib
import random
import shutil
import subprocess
import tempfile

random.seed(45)

BASE = pathlib.Path(r"C:\Users\vlad\Desktop\diploma-v2")
MANIFEST = BASE / "results" / "corpus_manifest.csv"
OUT = BASE / "data" / "corpus" / "evtx"
PER = 40
MIN_SIZE = 69_633
MAX_SIZE = 8_000_000

with open(MANIFEST, encoding="utf-8", newline="") as fh:
    rows = list(csv.reader(fh))
header, old = rows[0], rows[1:]
seen = {r[1] for r in old}
have = sum(1 for r in old if r[0] == "evtx")
need = PER - have
print("EVTX у маніфесті:", have, "потрібно додати:", need)

res = subprocess.run(["wevtutil", "el"], capture_output=True, text=True,
                     encoding="utf-8", errors="replace")
channels = [c.strip() for c in res.stdout.splitlines() if c.strip()]
random.shuffle(channels)
print("Каналів подій:", len(channels))

OUT.mkdir(parents=True, exist_ok=True)
tmp = pathlib.Path(tempfile.mkdtemp(prefix="evtx_"))
new_rows = []
tried = 0
skipped = collections.Counter()

for ch in channels:
    if len(new_rows) >= need:
        break
    tried += 1
    f = tmp / "export.evtx"
    try:
        r = subprocess.run(["wevtutil", "epl", ch, str(f), "/ow:true"],
                           capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        skipped["timeout"] += 1
        continue
    if r.returncode != 0 or not f.exists():
        skipped["немає доступу"] += 1
        continue
    size = f.stat().st_size
    if size < MIN_SIZE:
        skipped["порожній"] += 1
        f.unlink()
        continue
    if size > MAX_SIZE:
        skipped["завеликий"] += 1
        f.unlink()
        continue
    b = f.read_bytes()
    if b[:8] != b"ElfFile\x00":
        skipped["не EVTX"] += 1
        continue
    h = hashlib.sha256(b).hexdigest()
    if h in seen:
        skipped["дублікат"] += 1
        continue
    seen.add(h)
    shutil.copyfile(f, OUT / (h[:12] + ".evtx"))
    new_rows.append(["evtx", h, size, "evtx", "", f"wevtutil epl {ch}"])
    print(f"  +{len(new_rows):2d} {ch} ({size} Б)", flush=True)
    f.unlink()

shutil.rmtree(tmp, ignore_errors=True)

with open(MANIFEST, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(header)
    w.writerows(old)
    w.writerows(new_rows)

print(f"\nПеревірено каналів: {tried}, додано: {len(new_rows)}, пропущено: {dict(skipped)}")