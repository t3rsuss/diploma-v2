import csv
import hashlib
import io
import json
import os
import pathlib
import random
import shutil
import struct
import time
import xml.etree.ElementTree as ET
import zipfile
import zlib
import collections

random.seed(42)

BASE = pathlib.Path(__file__).resolve().parents[1]
OUT = BASE / "data" / "corpus"
MANIFEST = BASE / "results" / "corpus_manifest.csv"
ROOTS = [pathlib.Path(p) for p in (
    r"C:\Windows", r"C:\Program Files", r"C:\Program Files (x86)", r"C:\Users\vlad")]
SKIP = {"winsxs", "installer", "assembly", "servicing", "temp", "$recycle.bin",
        "node_modules", ".git", "appdata", "corpus", "malpe", "malelf", "mal",
        "diploma-v2", "diploma-final"}
PER = 40
CAND = 200
DIRCAP = 3
MAXB = 5_000_000
MAXT = 2_000_000
LIMIT_SEC = 900

EXT = {
    "png": "png", "jpg": "jpg", "jpeg": "jpg", "gif": "gif", "bmp": "bmp",
    "ico": "ico", "pdf": "pdf", "zip": "zip", "gz": "gz", "tgz": "gz",
    "7z": "7z", "sqlite": "sqlite", "db": "sqlite", "sqlite3": "sqlite",
    "wav": "wav", "mp3": "mp3", "json": "json", "xml": "xml", "html": "html",
    "htm": "html", "txt": "txt", "pcap": "pcap", "pcapng": "pcap",
    "ttf": "ttf", "otf": "ttf", "exe": "pe", "dll": "pe", "sys": "pe",
    "ocx": "pe", "efi": "pe", "so": "elf", "": "elf",
}
TEXT_FORMATS = {"json", "xml", "html", "txt"}


def decode_text(b):
    if b[:3] == b"\xef\xbb\xbf":
        return b[3:].decode("utf-8"), "utf-8-bom"
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return b.decode("utf-16"), "utf-16-bom"
    if len(b) >= 4 and b[0] != 0 and b[1] == 0 and b[3] == 0:
        return b.decode("utf-16-le"), "utf-16le"
    return b.decode("utf-8"), "utf-8"


def v_png(b):
    return b[:8] == b"\x89PNG\r\n\x1a\n" and b"IEND" in b[-16:]


def v_jpg(b):
    return b[:3] == b"\xff\xd8\xff" and b"\xff\xd9" in b[-64:]


def v_gif(b):
    return b[:6] in (b"GIF87a", b"GIF89a") and b[-1:] == b";"


def v_bmp(b):
    if b[:2] != b"BM" or len(b) < 26:
        return False
    size = struct.unpack("<I", b[2:6])[0]
    dib = struct.unpack("<I", b[14:18])[0]
    return size == len(b) and dib in (12, 40, 52, 56, 64, 108, 124)


def v_ico(b):
    if b[:4] != b"\x00\x00\x01\x00" or len(b) < 6:
        return False
    n = struct.unpack("<H", b[4:6])[0]
    return 1 <= n <= 64 and len(b) >= 6 + 16 * n


def v_pdf(b):
    return b[:5] == b"%PDF-" and b"%%EOF" in b[-1024:]


def v_zip(b):
    if b[:4] != b"PK\x03\x04":
        return False
    try:
        zipfile.ZipFile(io.BytesIO(b)).namelist()
        return True
    except Exception:
        return False


def v_gz(b):
    if b[:3] != b"\x1f\x8b\x08":
        return False
    try:
        zlib.decompressobj(31).decompress(b, 1_000_000)
        return True
    except Exception:
        return False


def v_7z(b):
    return b[:6] == b"7z\xbc\xaf\x27\x1c"


def v_sqlite(b):
    if b[:16] != b"SQLite format 3\x00" or len(b) < 100:
        return False
    ps = struct.unpack(">H", b[16:18])[0]
    return ps == 1 or (512 <= ps <= 32768 and ps & (ps - 1) == 0)


def v_wav(b):
    return b[:4] == b"RIFF" and b[8:12] == b"WAVE"


def v_mp3(b):
    return b[:3] == b"ID3" or (len(b) > 2 and b[0] == 0xFF and (b[1] & 0xE0) == 0xE0)


def v_pcap(b):
    return b[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                     b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a")


def v_ttf(b):
    return b[:4] in (b"\x00\x01\x00\x00", b"true", b"OTTO")


def v_pe(b):
    if b[:2] != b"MZ" or len(b) < 64:
        return False
    e = struct.unpack("<I", b[0x3C:0x40])[0]
    return e + 4 <= len(b) and b[e:e + 4] == b"PE\x00\x00"


def v_elf(b):
    return b[:4] == b"\x7fELF" and len(b) > 64


def v_json(b):
    t, enc = decode_text(b)
    if len(t.strip()) < 20:
        return False
    obj = json.loads(t)
    return isinstance(obj, (dict, list))


def v_xml(b):
    t, enc = decode_text(b)
    ET.fromstring(t)
    return True


def v_html(b):
    t, enc = decode_text(b)
    head = t[:2000].lower()
    return "<html" in head or "<!doctype html" in head


def v_txt(b):
    t, enc = decode_text(b)
    if len(t) < 200 or t.lstrip()[:1] in ("<", "{", "["):
        return False
    ok = sum(1 for c in t if c.isprintable() or c in "\r\n\t")
    return ok / len(t) >= 0.97


VALID = {
    "png": v_png, "jpg": v_jpg, "gif": v_gif, "bmp": v_bmp, "ico": v_ico,
    "pdf": v_pdf, "zip": v_zip, "gz": v_gz, "7z": v_7z, "sqlite": v_sqlite,
    "wav": v_wav, "mp3": v_mp3, "pcap": v_pcap, "ttf": v_ttf, "pe": v_pe,
    "elf": v_elf, "json": v_json, "xml": v_xml, "html": v_html, "txt": v_txt,
}


def encoding_of(fmt, b):
    if fmt in TEXT_FORMATS:
        try:
            return decode_text(b)[1]
        except Exception:
            return ""
    return ""


cands = collections.defaultdict(list)
dircount = collections.Counter()
seen = set()
walked = 0
t0 = time.time()
stop = False

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
                      f"зібрано {sum(len(v) for v in cands.values())}", flush=True)
            ext = os.path.splitext(name)[1].lower().lstrip(".")
            fmt = EXT.get(ext)
            if fmt is None or len(cands[fmt]) >= CAND:
                continue
            if dircount[(fmt, dp)] >= DIRCAP:
                continue
            p = pathlib.Path(dp) / name
            try:
                size = p.stat().st_size
                limit = MAXT if fmt in TEXT_FORMATS else MAXB
                if size < 512 or size > limit:
                    continue
                b = p.read_bytes()
            except OSError:
                continue
            try:
                if not VALID[fmt](b):
                    continue
            except Exception:
                continue
            h = hashlib.sha256(b).hexdigest()
            if h in seen:
                continue
            seen.add(h)
            dircount[(fmt, dp)] += 1
            cands[fmt].append((h, size, ext, encoding_of(fmt, b), str(p)))
        if time.time() - t0 > LIMIT_SEC or all(
                len(cands[f]) >= CAND for f in set(EXT.values())):
            stop = True
            break

print(f"\nобхід завершено: {walked} файлів, {time.time() - t0:.0f} с\n")

OUT.mkdir(parents=True, exist_ok=True)
MANIFEST.parent.mkdir(parents=True, exist_ok=True)
rows = []
for fmt in sorted(set(EXT.values())):
    pool = cands.get(fmt, [])
    pick = random.sample(pool, min(PER, len(pool)))
    d = OUT / fmt
    d.mkdir(exist_ok=True)
    for h, size, ext, enc, src in pick:
        dst = d / (h[:12] + ("." + ext if ext else ""))
        shutil.copyfile(src, dst)
        rows.append([fmt, h, size, ext, enc, src])
    print(f"{fmt:7s} кандидатів {len(pool):4d}, у корпусі {len(pick):3d}")

with open(MANIFEST, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["format", "sha256", "size", "ext", "encoding", "src"])
    w.writerows(rows)

print(f"\nманіфест: {MANIFEST}")
print(f"усього файлів у корпусі: {len(rows)}")