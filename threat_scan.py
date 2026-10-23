"""Пошук прихованих даних за слідом читання.

Ідея: легітимна програма-читач не торкається частини байтів файла (дописаний хвіст, пропущені блоки).
Якщо в таких ділянках знайдено виконувані файли, архіви чи інші вкладені об'єкти, файл підозрілий.
"""
import argparse
import importlib
import json
import math
import pathlib
import sys

MIN_REGION = 16
HIGH_ENTROPY, MIN_ENTROPY_REGION = 7.5, 256

SIGNATURES = [
    ("архів ZIP", b"PK\x03\x04", "mid"),
    ("архів GZIP", b"\x1f\x8b\x08", "mid"),
    ("документ PDF", b"%PDF-", "mid"),
    ("архів RAR", b"Rar!\x1a\x07", "mid"),
    ("архів 7z", b"7z\xbc\xaf\x27\x1c", "mid"),
    ("скрипт (shebang)", b"#!/", "mid"),
]
LEVEL_ORDER = {"low": 0, "mid": 1, "high": 2}


def entropy(block):
    if not block:
        return 0.0
    counts = [0] * 256
    for b in block:
        counts[b] += 1
    n = len(block)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def is_pe(data, off):
    if data[off:off + 2] != b"MZ" or off + 0x40 > len(data):
        return False
    e_lfanew = int.from_bytes(data[off + 0x3C:off + 0x40], "little")
    return 0x40 <= e_lfanew <= 0x400 and data[off + e_lfanew:off + e_lfanew + 4] == b"PE\x00\x00"


def is_elf(data, off):
    h = data[off:off + 7]
    return len(h) == 7 and h[:4] == b"\x7fELF" and h[4] in (1, 2) and h[5] in (1, 2) and h[6] == 1


def _find_signatures_local(data, start, end):
    hits = []
    i = data.find(b"MZ", start, end)
    while i != -1:
        if is_pe(data, i):
            hits.append({"offset": i, "kind": "виконуваний файл PE", "level": "high"})
        i = data.find(b"MZ", i + 1, end)
    i = data.find(b"\x7fELF", start, end)
    while i != -1:
        if is_elf(data, i):
            hits.append({"offset": i, "kind": "виконуваний файл ELF", "level": "high"})
        i = data.find(b"\x7fELF", i + 1, end)
    for kind, sig, level in SIGNATURES:
        i = data.find(sig, start, end)
        while i != -1:
            hits.append({"offset": i, "kind": kind, "level": level})
            i = data.find(sig, i + 1, end)
    return sorted(hits, key=lambda h: h["offset"])


def find_signatures(data, start, end):
    if not 0 <= start <= end <= len(data):
        raise ValueError("Invalid scan interval")
    region = data[start:end]
    return [
        {**hit, "offset": start + hit["offset"]}
        for hit in _find_signatures_local(region, 0, len(region))
    ]


def unread_regions(size, reads):
    covered = sorted((max(0, p), min(size, p + l)) for p, l in reads if l > 0)
    regions, cursor = [], 0
    for a, b in covered:
        if a > cursor:
            regions.append((cursor, a))
        cursor = max(cursor, b)
    if cursor < size:
        regions.append((cursor, size))
    return regions


def scan(data, log, min_region=MIN_REGION):
    """log: список читань (pos, len, ctx) або (pos, len)."""
    reads = [(r[0], r[1]) for r in log]
    findings, level = [], "low"
    all_unread = unread_regions(len(data), reads)
    for a, b in all_unread:
        if b - a < min_region:
            continue
        ent = entropy(data[a:b])
        hits = find_signatures(data, a, b)
        region_level = max((h["level"] for h in hits), key=LEVEL_ORDER.get, default="low")
        note = None
        if region_level == "low" and b - a >= MIN_ENTROPY_REGION and ent >= HIGH_ENTROPY:
            region_level, note = "mid", "велика ділянка з високою ентропією (стиснені або зашифровані дані)"
        findings.append({
            "start": a, "end": b, "size": b - a, "entropy": round(ent, 2),
            "signatures": hits, "level": region_level, "note": note,
        })
        if LEVEL_ORDER[region_level] > LEVEL_ORDER[level]:
            level = region_level
    return {
        "file_size": len(data),
        "unread_bytes": sum(b - a for a, b in all_unread),
        "scanned_unread_bytes": sum(f["size"] for f in findings),
        "skipped_unread_bytes": sum(
            b - a for a, b in all_unread if b - a < min_region
        ),
        "regions": findings,
        "level": level,
    }


def main():
    here = pathlib.Path(__file__).resolve().parent
    sys.path.insert(0, str(here / "experiments"))
    sys.path.insert(0, str(pathlib.Path.cwd()))
    import e18_context as CTX

    ap = argparse.ArgumentParser(description="Пошук прихованих даних за слідом читання")
    ap.add_argument("path")
    ap.add_argument("--format", choices=["png", "gif", "ico", "wav", "gz", "docx"])
    ap.add_argument("--reader", help="модуль:функція (приймає файловий об'єкт)")
    a = ap.parse_args()
    data = pathlib.Path(a.path).read_bytes()
    if a.reader:
        mod, _, name = a.reader.partition(":")
        f = CTX.CtxIO(data)
        getattr(importlib.import_module(mod), name)(f)
        log = f.log
    elif a.format:
        log = CTX.run_ctx(a.format, data)
    else:
        raise SystemExit("потрібно вказати --format або --reader")
    print(json.dumps(scan(data, log), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
