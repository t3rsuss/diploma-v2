import collections
import csv
import hashlib
import io
import os
import pathlib
import random
import re
import shutil
import struct
import time
import zipfile

random.seed(43)

BASE = pathlib.Path(__file__).resolve().parents[1]
OUT = BASE / "data" / "corpus"
MANIFEST = BASE / "results" / "corpus_manifest.csv"
BACKUP = BASE / "results" / "corpus_manifest.v1.csv"
SAMPLES = BASE / "samples"
ROOTS = [pathlib.Path(p) for p in (
    r"C:\Users\vlad", r"C:\ProgramData", r"C:\Program Files",
    r"C:\Program Files (x86)", r"C:\Windows")]
SKIP = {"winsxs", "installer", "assembly", "servicing", "temp", "$recycle.bin",
        "node_modules", ".git", "corpus", "malpe", "malelf", "mal",
        "diploma-v2", "diploma-final", "cache", "code cache", "gpucache"}
PRIVATE = ("login", "cookie", "password", "web data", "autofill", "payment", "token")
PER = 40
DIRCAP = 3
MAXB = 5_000_000
MAXDB = 30_000_000
MAXT = 2_000_000
LIMIT_SEC = 900

EXT = {
    "docx": "docx", "xlsx": "xlsx", "pptx": "pptx",
    "doc": "ole2", "xls": "ole2", "ppt": "ole2", "msi": "ole2",
    "rtf": "rtf", "evtx": "evtx", "lnk": "lnk",
    "log": "log", "ini": "ini", "cfg": "ini", "conf": "ini", "csv": "csv",
    "db": "sqlite", "sqlite": "sqlite", "sqlite3": "sqlite", "": "sqlite",
}
TEXT_FORMATS = {"log", "ini", "csv"}
LNK_GUID = bytes.fromhex("0114020000000000c000000000000046")


def decode_text(b):
    if b[:3] == b"\xef\xbb\xbf":
        return b[3:].decode("utf-8"), "utf-8-bom"
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return b.decode("utf-16"), "utf-16-bom"
    if len(b) >= 4 and b[0] != 0 and b[1] == 0 and b[3] == 0:
        return b.decode("utf-16-le"), "utf-16le"
    return b.decode("utf-8"), "utf-8"


def ooxml(prefix):
    def check(b, ext):
        if b[:4] != b"PK\x03\x04":
            return False
        names = zipfile.ZipFile(io.BytesIO(b)).namelist()
        return "[Content_Types].xml" in names and any(n.startswith(prefix) for n in names)
    return check


def v_ole2(b, ext):
    return b[:8] == bytes.fromhex("d0cf11e0a1b11ae1") and len(b) >= 1536


def v_rtf(b, ext):
    return b[:5] == b"{\\rtf"


def v_evtx(b, ext):
    return b[:8] == b"ElfFile\x00"


def v_lnk(b, ext):
    return b[:4] == b"\x4c\x00\x00\x00" and b[4:20] == LNK_GUID


def v_sqlite(b, ext):
    if b[:16] != b"SQLite format 3\x00" or len(b) < 100:
        return False
    ps = struct.unpack(">H", b[16:18])[0]
    return ps == 1 or (512 <= ps <= 32768 and ps & (ps - 1) == 0)


def v_log(b, ext):
    t, _ = decode_text(b)
    lines = [ln for ln in t.splitlines() if ln.strip()]
    if len(t) < 200 or len(lines) < 10 or "\x00" in t:
        return False
    if t.lstrip()[:1] in ("<", "{", "["):
        return False
    ok = sum(1 for c in t if c.isprintable() or c in "\r\n\t")
    return ok / len(t) >= 0.97 and sum(len(x) for x in lines) / len(lines) < 400


def v_ini(b, ext):
    t, _ = decode_text(b)
    if len(t) < 100 or "\x00" in t:
        return False
    section = re.search(r"^\s*\[[^\]\r\n]+\]\s*$", t, re.M) is not None
    kv = len(re.findall(r"^\s*[\w.\-]+\s*[=:]\s*\S*", t, re.M))
    return kv >= 3 and (section or kv >= 8)


def v_csv(b, ext):
    t, _ = decode_text(b)
    lines = [ln for ln in t.splitlines() if ln.strip()][:50]
    if len(lines) < 5 or "\x00" in t:
        return False
    for d in (",", ";", "\t"):
        counts = [ln.count(d) for ln in lines]
        mode, freq = collections.Counter(counts).most_common(1)[0]
        if mode >= 1 and freq / len(counts) >= 0.8:
            return True
    return False


VALID = {
    "docx": ooxml("word/"), "xlsx": ooxml("xl/"), "pptx": ooxml("ppt/"),
    "ole2": v_ole2, "rtf": v_rtf, "evtx": v_evtx, "lnk": v_lnk,
    "sqlite": v_sqlite, "log": v_log, "ini": v_ini, "csv": v_csv,
}


def encoding_of(fmt, b):
    if fmt in TEXT_FORMATS:
        try:
            return decode_text(b)[1]
        except Exception:
            return ""
    return ""


rows = []
with open(MANIFEST, encoding="utf-8", newline="") as fh:
    rows = list(csv.reader(fh))
header, old = rows[0], rows[1:]
shutil.copyfile(MANIFEST, BACKUP)
existing = collections.Counter(r[0] for r in old)
seen = {r[1] for r in old}
formats = set(EXT.values()) | {"elf"}
need = {f: PER - existing[f] for f in formats}
print("Потрібно додати:", {f: n for f, n in sorted(need.items()) if n > 0})

found = collections.defaultdict(list)
dircount = collections.Counter()
walked = 0
t0 = time.time()
stop = False
scan_fmts = set(EXT.values())

for root in ROOTS:
    if not root.exists() or stop:
        continue
    for dp, dn, fn in os.walk(root, onerror=lambda e: None):
        dn[:] = [d for d in dn if d.lower() not in SKIP]
        random.shuffle(dn)
        random.shuffle(fn)
        for name in fn:
            walked += 1
            if walked % 50000 == 0:
                print(f"переглянуто {walked}, {time.time() - t0:.0f} с, "
                      f"зібрано {sum(len(v) for v in found.values())}", flush=True)
            ext = os.path.splitext(name)[1].lower().lstrip(".")
            fmt = EXT.get(ext)
            if fmt is None or len(found[fmt]) >= need[fmt]:
                continue
            if dircount[(fmt, dp)] >= DIRCAP:
                continue
            if fmt == "sqlite" and any(k in name.lower() for k in PRIVATE):
                continue
            p = pathlib.Path(dp) / name
            try:
                size = p.stat().st_size
                limit = MAXT if fmt in TEXT_FORMATS else (MAXDB if fmt == "sqlite" else MAXB)
                if size < 512 or size > limit:
                    continue
                if fmt == "sqlite":
                    with open(p, "rb") as f:
                        if f.read(16) != b"SQLite format 3\x00":
                            continue
                b = p.read_bytes()
            except OSError:
                continue
            try:
                if not VALID[fmt](b, ext):
                    continue
            except Exception:
                continue
            h = hashlib.sha256(b).hexdigest()
            if h in seen:
                continue
            seen.add(h)
            dircount[(fmt, dp)] += 1
            found[fmt].append((h, size, ext, encoding_of(fmt, b), str(p)))
        if time.time() - t0 > LIMIT_SEC or all(len(found[f]) >= need[f] for f in scan_fmts):
            stop = True
            break

print(f"\nобхід завершено: {walked} файлів, {time.time() - t0:.0f} с")

groups = collections.defaultdict(list)
if need["elf"] > 0 and SAMPLES.exists():
    for dp, dn, fn in os.walk(SAMPLES):
        dn[:] = [d for d in dn if not d.lower().startswith("mal")]
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
    for g in groups.values():
        random.shuffle(g)
    picks = []
    while len(picks) < need["elf"] and any(groups.values()):
        for m in sorted(groups):
            if groups[m] and len(picks) < need["elf"]:
                picks.append((m, groups[m].pop()))
    for m, p in picks:
        b = p.read_bytes()
        h = hashlib.sha256(b).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        found["elf"].append((h, len(b), p.suffix.lower().lstrip("."), f"e_machine={m}", str(p)))
    print("ELF з samples за архітектурами (e_machine):",
          {m: len(v) for m, v in sorted(groups.items())})

new_rows = []
for fmt in sorted(found):
    d = OUT / fmt
    d.mkdir(parents=True, exist_ok=True)
    for h, size, ext, enc, src in found[fmt]:
        dst = d / (h[:12] + ("." + ext if ext else ""))
        shutil.copyfile(src, dst)
        new_rows.append([fmt, h, size, ext, enc, src])

with open(MANIFEST, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(header)
    w.writerows(old)
    w.writerows(new_rows)

total = collections.Counter(r[0] for r in old) + collections.Counter(r[0] for r in new_rows)
print("\nКлас: було -> додано -> всього")
for f in sorted(total | collections.Counter(formats)):
    print(f"  {f:7s} {existing[f]:3d} -> +{len(found[f]):3d} -> {total[f]:3d}")
print(f"\nУсього файлів у корпусі: {sum(total.values())}")
print("Маніфест:", MANIFEST, "(копія старого:", BACKUP, ")")