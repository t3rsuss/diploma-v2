import os
import pathlib
import time
import collections

import pandas as pd

CSV = pathlib.Path("results/format_recognition.csv")
ROOTS = [pathlib.Path(p) for p in (
    r"C:\Windows", r"C:\Program Files", r"C:\Program Files (x86)", r"C:\Users\vlad")]
SKIP = {"winsxs", "installer", "assembly", "servicing", "temp",
        "$recycle.bin", "node_modules", ".git", "appdata"}
LIMIT_SEC = 600

TEXT_LIKE = {"txt", "tsv", "csv", "ini", "markdown", "yaml", "toml", "json",
             "jsonl", "javascript", "xml", "html", "winregistry", "log"}
OK = {
    "json": {"json", "jsonl"},
    "zip": {"zip", "jar", "docx", "xlsx", "pptx", "odt", "apk", "epub"},
    "html": {"html"},
    "txt": TEXT_LIKE,
}

df = pd.read_csv(CSV)
o = df[df["condition"] == "orig"]
mask = [t in OK and m not in OK[t] for t, m in zip(o["true"], o["magika"])]
bad = o[mask]
want = {n: (t, m, s) for n, t, m, s in
        zip(bad["file"], bad["true"], bad["magika"], bad["magika_score"])}
print(f"Файлів для перевірки: {len(want)}")

found = {}
t0 = time.time()
done = False
for root in ROOTS:
    if not root.exists():
        continue
    for dp, dn, fn in os.walk(root, onerror=lambda e: None):
        dn[:] = [d for d in dn if d.lower() not in SKIP]
        for name in fn:
            if name in want and name not in found:
                found[name] = pathlib.Path(dp) / name
        if len(found) == len(want) or time.time() - t0 > LIMIT_SEC:
            done = True
            break
    if done:
        break

print(f"Знайдено на диску: {len(found)} з {len(want)}, {time.time() - t0:.0f} с\n")

stat = collections.Counter()
for name, p in sorted(found.items(), key=lambda kv: (want[kv[0]][0], kv[0])):
    t, m, s = want[name]
    try:
        with open(p, "rb") as f:
            head = f.read(16)
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 8))
            tail = f.read(8)
    except OSError:
        continue
    if head[:3] == b"\xef\xbb\xbf" or head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        tag = "BOM"
    elif head[:2] == b"PK":
        tag = "PK"
    elif size == 0:
        tag = "EMPTY"
    else:
        tag = "OTHER"
    stat[(t, m, tag)] += 1
    print(f"{t:5s} -> {m:11s} {s:.2f} {size:>9d} Б {tag:5s} head={head.hex(' ')} tail={tail.hex(' ')}")
    print(f"      {p}")

print("\nПідсумок (істина, мітка Magika, тип початку):")
for k, v in sorted(stat.items()):
    print(f"{v:3d}  {k}")
