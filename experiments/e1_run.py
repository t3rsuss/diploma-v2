import csv
import hashlib
import pathlib
import random
import time

import magic
from magika import Magika

BASE = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = BASE / "results" / "corpus_manifest.csv"
CORPUS = BASE / "data" / "corpus"
OUT = BASE / "results" / "e1_v2.csv"

m = Magika()
COLS = ["fmt", "sha12", "size", "ext", "condition", "ext_shown",
        "magika", "magika_dl", "magika_score", "libmagic_mime", "libmagic_desc"]


def identify(data):
    try:
        r = m.identify_bytes(data)
        if r.ok:
            label = str(r.output.label)
            score = round(float(r.score), 3)
            dl = str(getattr(getattr(r, "dl", None), "label", ""))
        else:
            label, score, dl = "error", 0.0, ""
    except Exception:
        label, score, dl = "error", 0.0, ""
    try:
        mime = magic.from_buffer(data, mime=True)
        desc = magic.from_buffer(data)[:80]
    except Exception:
        mime, desc = "error", ""
    return label, dl, score, mime, desc


def variants(fmt, data, ext, sha):
    rng = random.Random(int(sha[:8], 16))
    size = len(data)
    out = [("orig", data, ext)]
    z = bytearray(data)
    z[:16] = b"\x00" * 16
    out.append(("zero_header", bytes(z), ext))
    r = bytearray(data)
    r[:16] = bytes(rng.randrange(256) for _ in range(16))
    out.append(("random_header", bytes(r), ext))
    out.append(("trunc_tail", data[: max(size // 2, 1)], ext))
    start = max(size // 2 - 2048, 0)
    out.append(("fragment", data[start:start + 4096], ext))
    if fmt in ("pe", "elf"):
        out.append(("spoof_jpg", data, "jpg"))
        out.append(("spoof_txt", data, "txt"))
    return out


with open(MANIFEST, encoding="utf-8", newline="") as fh:
    items = list(csv.DictReader(fh))
items.sort(key=lambda r: (r["format"], r["sha256"]))

t0 = time.time()
n_rows = 0
last_fmt = None
with open(OUT, "w", newline="", encoding="utf-8") as fo:
    w = csv.writer(fo)
    w.writerow(COLS)
    for it in items:
        fmt, sha, ext = it["format"], it["sha256"], it["ext"]
        src = CORPUS / fmt / (sha[:12] + ("." + ext if ext else ""))
        if not src.exists():
            print("немає файла:", src)
            continue
        if fmt != last_fmt:
            if last_fmt:
                fo.flush()
                print(f"готово {last_fmt}, {time.time() - t0:.0f} с, рядків {n_rows}", flush=True)
            last_fmt = fmt
        data = src.read_bytes()
        for cond, d, shown in variants(fmt, data, ext, sha):
            label, dl, score, mime, desc = identify(d)
            w.writerow([fmt, sha[:12], len(data), ext, cond, shown,
                        label, dl, score, mime, desc])
            n_rows += 1
    fo.flush()

print(f"\nготово {last_fmt}. Усього рядків: {n_rows}, час {time.time() - t0:.0f} с")
print("Результат:", OUT)