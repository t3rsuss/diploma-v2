import collections
import csv
import os
import pathlib
import random
import sys

import magic
from magika import Magika

random.seed(42)
SRC = [pathlib.Path(p) for p in sys.argv[1].split(";")]
OUT = pathlib.Path(sys.argv[2])

EXT = {"png", "jpg", "gif", "bmp", "ico", "pdf", "zip", "gz", "7z", "sqlite", "db",
       "wav", "mp3", "json", "xml", "html", "txt", "pcap", "ttf"}
PE_EXT = {"exe", "dll", "sys", "ocx"}
SKIP_DIRS = {"winsxs", "installer", "assembly", "servicing", "temp",
             "$recycle.bin", "node_modules", ".git"}
PER = 30
CAND = PER * 3
MAXB = 2_000_000
MAX_PER_ROOT = 60_000

found = collections.defaultdict(list)


def head4(p):
    try:
        with open(p, "rb") as f:
            return f.read(4)
    except OSError:
        return b""


for root_dir in SRC:
    is_elf_root = "elf_clean" in str(root_dir).lower()
    n = 0
    for dp, dn, fn in os.walk(root_dir, onerror=lambda e: None):
        dn[:] = [d for d in dn if d.lower() not in SKIP_DIRS]
        for name in fn:
            n += 1
            p = pathlib.Path(dp) / name
            ext = p.suffix.lower().lstrip(".")
            if is_elf_root:
                key = "elf" if ext == "" else None
            elif ext in PE_EXT:
                key = "pe"
            elif ext in EXT:
                key = ext
            else:
                key = None
            if key is None or len(found[key]) >= CAND:
                continue
            try:
                size = p.stat().st_size
            except OSError:
                continue
            if size < 512 or size > 50_000_000:
                continue
            h = head4(p)
            if key == "pe" and h[:2] != b"MZ":
                continue
            if key == "elf" and h != b"\x7fELF":
                continue
            found[key].append(p)
        if n > MAX_PER_ROOT:
            break
    print(f"обхід {root_dir}: переглянуто {n}, знайдено класів {len(found)}", flush=True)

m = Magika()
rows = []
for key, paths in sorted(found.items()):
    random.shuffle(paths)
    for p in paths[:PER]:
        try:
            data = p.read_bytes()[:MAXB]
        except OSError:
            continue
        shown = p.suffix.lower().lstrip(".")
        variants = [("orig", data, shown)]
        broken = bytearray(data)
        broken[:16] = b"\x00" * 16
        variants.append(("zero_header", bytes(broken), shown))
        if key in ("pe", "elf"):
            variants.append(("spoof_jpg", data, "jpg"))
        for cond, d, ext_shown in variants:
            r = m.identify_bytes(d)
            label = r.output.label if r.ok else "error"
            score = round(float(r.score), 3) if r.ok else 0.0
            rows.append([p.name, key, cond, ext_shown, label, score,
                         magic.from_buffer(d, mime=True)])
    print("готово:", key, min(len(paths), PER), flush=True)

OUT.parent.mkdir(parents=True, exist_ok=True)
with open(OUT, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["file", "true", "condition", "ext_shown", "magika", "magika_score", "libmagic_mime"])
    w.writerows(rows)

print("\nНайчастіші мітки Magika за істинним класом (стан orig):")
cnt = collections.defaultdict(collections.Counter)
for r in rows:
    if r[2] == "orig":
        cnt[r[1]][r[4]] += 1
for k, c in sorted(cnt.items()):
    print(f"{k:8s}", sum(c.values()), c.most_common(3))