import struct

from threat_scan import find_signatures, scan


def pe_stub():
    data = bytearray(100)
    data[:2] = b"MZ"
    data[0x3C:0x40] = struct.pack("<I", 0x40)
    data[0x40:0x44] = b"PE\x00\x00"
    return bytes(data)


def test_short_unread_region_is_counted_but_not_scanned():
    data = b"A" * 20
    result = scan(data, [(0, 15)])
    assert result["unread_bytes"] == 5
    assert result["scanned_unread_bytes"] == 0
    assert result["skipped_unread_bytes"] == 5
    assert result["regions"] == []


def test_pe_confirmation_cannot_cross_region_end():
    data = pe_stub()
    assert find_signatures(data, 0, 0x40) == []


def test_elf_confirmation_cannot_cross_region_end():
    data = b"\x7fELF\x02\x01\x01" + b"\x00" * 20
    assert find_signatures(data, 0, 4) == []


def test_signature_offsets_remain_absolute():
    prefix = b"A" * 23
    region = pe_stub()
    data = prefix + region + b"B" * 10
    hits = find_signatures(data, len(prefix), len(prefix) + len(region))
    assert len(hits) == 1
    assert hits[0]["offset"] == len(prefix)
    assert hits[0]["level"] == "high"
