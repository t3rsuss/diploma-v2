import collections
import csv
import hashlib
import io
import pathlib
import sys
import zipfile

BASE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from src.triage.fragment import check_content

GD = BASE / "data" / "govdocs"
MAXB = 50_000_000
EXT = {
    "pdf": "pdf", "doc": "ole2", "xls": "ole2", "ppt": "ole2", "html": "html",
    "htm": "html", "txt": "txt", "xml": "xml", "csv": "csv", "jpg": "jpg",
    "jpeg": "jpg", "gif": "gif", "png": "png", "gz": "gz", "wav": "wav",
    "rtf": "rtf", "ttf": "ttf", "ico": "ico", "exe": "pe", "dll": "pe",
    "log": "log", "ini": "ini", "json": "json", "docx": "docx",
}
SKIP_EXT = {"zip", "xlsx", "pptx", "sqlite", "db", "lnk", "evtx", "elf", "so", ""}


def check(cls, b):
    if cls == "ole2":
        return b[:8] == bytes.fromhex("d0cf11e0a1b11ae1")
    if cls == "rtf":
        return b[:5] == b"{\\rtf"
    if cls == "pe":
        if b[:2] != b"MZ" or len(b) < 64:
            return False
        e = int.from_bytes(b[0x3C:0x40], "little")
        return e + 4 <= len(b) and b[e:e + 4] == b"PE\x00\x00"
    if cls == "docx":
        try:
            names = zipfile.ZipFile(io.BytesIO(b)).namelist()
            return "word/document.xml" in names
        except Exception:
            return False
    return check_content(cls, b)


def scan(root, seen):
    rows, rejected = [], collections.Counter()
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        ext = p.suffix.lower().lstrip(".")
        if ext in SKIP_EXT:
            continue
        try:
            size = p.stat().st_size
            if size < 512 or size > MAXB:
                continue
            b = p.read_bytes()
        except OSError:
            continue
        h = hashlib.sha256(b).hexdigest()
        if h in seen:
            continue
        cls = EXT.get(ext)
        if cls is None:
            cls = "other"
        else:
            try:
                ok = check(cls, b)
            except Exception:
                ok = False
            if not ok:
                rejected[cls] += 1
                continue
        seen.add(h)
        rows.append([cls, h, size, ext, str(p)])
    return rows, rejected


def save(rows, name):
    out = BASE / "results" / name
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["format", "sha256", "size", "ext", "src"])
        w.writerows(rows)


seen = set()
dev, rej_dev = scan(GD / "dev", seen)
test, rej_test = scan(GD / "test", seen)
for extra, tgt, rej in (("dev_extra", dev, rej_dev), ("test_extra", test, rej_test)):
    if (GD / extra).exists():
        r, rj = scan(GD / extra, seen)
        tgt.extend(r)
        rej.update(rj)
save(dev, "govdocs_dev.csv")
save(test, "govdocs_test.csv")

cd = collections.Counter(r[0] for r in dev)
ct = collections.Counter(r[0] for r in test)
print(f"{'клас':8s}{'dev':>6s}{'test':>6s}{'відхилено dev':>15s}{'відхилено test':>16s}")
for c in sorted(set(cd) | set(ct) | set(rej_dev) | set(rej_test)):
    print(f"{c:8s}{cd[c]:6d}{ct[c]:6d}{rej_dev[c]:15d}{rej_test[c]:16d}")
print(f"\nРазом dev {len(dev)}, test {len(test)}")
oe = collections.Counter(r[3] for r in dev + test if r[0] == "other")
print("Найчастіші розширення класу other:", oe.most_common(12))