import os

from block_scan import entropy, scan_block, scan_file


def pe_blob(size=300):
    body = bytearray(os.urandom(size))
    body[0:2] = b"MZ"
    body[0x3C:0x40] = (0x80).to_bytes(4, "little")
    body[0x80:0x84] = b"PE\x00\x00"
    return bytes(body)


def kinds(findings):
    return {f["kind"] for f in findings}


def test_plain_pe_is_found_at_offset():
    block = b"A" * 50 + pe_blob()
    found = scan_block(block, base=1000)
    assert any(f["kind"] == "вбудований PE-файл" and f["offset"] == 1050 for f in found)
    assert all(f["severity"] == "високий" for f in found if f["kind"] == "вбудований PE-файл")


def test_xor_pe_is_found_with_key():
    key = 0x5A
    block = bytes(b ^ key for b in pe_blob())
    found = scan_block(block)
    assert any("XOR" in f["kind"] and "0x5a" in f["detail"] for f in found)


def test_mz_without_pe_header_is_ignored():
    block = b"MZ" + b"\x00" * 200
    assert not any("PE" in f["kind"] for f in scan_block(block))


def test_elf_is_found():
    block = b"\x00" * 10 + b"\x7fELF\x02\x01\x01" + b"\x00" * 100
    assert "вбудований ELF-файл" in kinds(scan_block(block))


def test_plain_text_has_no_findings():
    assert scan_block(b"alpha bravo delta echo " * 40) == []


def test_random_block_gets_medium_entropy_finding():
    found = scan_block(os.urandom(600))
    assert any(f["severity"] == "середній" for f in found)


def test_short_block_is_not_flagged_by_entropy():
    assert not any(f["severity"] == "середній" for f in scan_block(os.urandom(100)))


def test_url_and_ip_are_low_severity():
    found = scan_block(b"see https://example.org/path and 192.168.1.10 now")
    assert {"URL у даних", "IP-адреса у даних"} <= kinds(found)
    assert all(f["severity"] == "низький" for f in found)


def test_invalid_ip_is_ignored():
    assert "IP-адреса у даних" not in kinds(scan_block(b"value 999.1.1.1 end"))


def test_scan_file_only_scans_data_blocks():
    data = b"HDR!" + pe_blob()
    fields = [(0, 4, "константа"), (4, len(data), "дані (блок)")]
    assert scan_file(data, fields)
    assert scan_file(data, [(0, len(data), "змінне поле")]) == []


def test_entropy_bounds():
    assert entropy(b"") == 0.0
    assert entropy(b"\x00" * 100) == 0.0
    assert abs(entropy(bytes(range(256)) * 4) - 8.0) < 1e-9
