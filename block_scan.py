"""Аналіз вмісту блоків даних, виділених відновленою структурою."""
import math
import re

ENT_MIN_LEN, ENT_MEDIUM = 256, 7.0
XOR_WINDOW = 0x400

URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{4,200}")
IP_RE = re.compile(rb"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def entropy(block):
    if not block:
        return 0.0
    counts = [0] * 256
    for b in block:
        counts[b] += 1
    n = len(block)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def _pe_at(buf, off):
    if buf[off:off + 2] != b"MZ" or off + 0x40 > len(buf):
        return False
    e = int.from_bytes(buf[off + 0x3C:off + 0x40], "little")
    return 0x40 <= e <= XOR_WINDOW - 4 and buf[off + e:off + e + 4] == b"PE\x00\x00"


def _find_all(buf, pattern, limit=16):
    pos, found = buf.find(pattern), []
    while pos != -1 and len(found) < limit:
        found.append(pos)
        pos = buf.find(pattern, pos + 1)
    return found


def find_plain_pe(block):
    return [p for p in _find_all(block, b"MZ") if _pe_at(block, p)]


def find_elf(block):
    return [p for p in _find_all(block, b"\x7fELF")
            if p + 6 <= len(block) and block[p + 4] in (1, 2) and block[p + 5] in (1, 2)]


def find_xor_pe(block):
    hits = []
    for key in range(1, 256):
        pattern = bytes([0x4D ^ key, 0x5A ^ key])
        for p in _find_all(block, pattern, limit=8):
            window = bytes(x ^ key for x in block[p:p + XOR_WINDOW])
            if _pe_at(window, 0):
                hits.append((p, key))
    return hits


def _valid_ip(raw):
    return all(int(x) <= 255 for x in raw.split(b"."))


def scan_block(block, base=0):
    findings = []
    for p in find_plain_pe(block):
        findings.append({"offset": base + p, "kind": "вбудований PE-файл", "severity": "високий",
                         "detail": "заголовки MZ і PE на коректних зсувах"})
    for p in find_elf(block):
        findings.append({"offset": base + p, "kind": "вбудований ELF-файл", "severity": "високий",
                         "detail": "сигнатура ELF з коректними класом і порядком байтів"})
    for p, key in find_xor_pe(block):
        findings.append({"offset": base + p, "kind": "PE-файл, закодований XOR", "severity": "високий",
                         "detail": f"ключ 0x{key:02x}, після декодування заголовки MZ і PE коректні"})
    if not any(f["severity"] == "високий" for f in findings):
        h = entropy(block)
        if len(block) >= ENT_MIN_LEN and h >= ENT_MEDIUM:
            findings.append({"offset": base, "kind": "блок з високою ентропією", "severity": "середній",
                             "detail": f"ентропія {h:.2f} біт/байт: стиснені або зашифровані дані"})
    for m in URL_RE.finditer(block):
        findings.append({"offset": base + m.start(), "kind": "URL у даних", "severity": "низький",
                         "detail": m.group().decode("ascii", "replace")[:80]})
    for m in IP_RE.finditer(block):
        if _valid_ip(m.group()):
            findings.append({"offset": base + m.start(), "kind": "IP-адреса у даних", "severity": "низький",
                             "detail": m.group().decode("ascii")})
    return findings


def scan_file(data, fields):
    """fields: список (початок, кінець, роль). Скануються лише блоки даних."""
    findings = []
    for a, b, role in fields:
        if role != "дані (блок)":
            continue
        for f in scan_block(data[a:b], a):
            f["block"] = (a, b)
            findings.append(f)
    return findings
