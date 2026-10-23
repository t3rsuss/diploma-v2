import pathlib
import random
import struct
import zlib

import e18_context as CTX

CTX.GENERIC.add("read_exact")

OUT = pathlib.Path(__file__).resolve().parent / "samples_xdt3"
TYPES = [1, 2, 3, 4, 5, 6]
HEADER = struct.Struct("<4sBBHHII")


def varint(value):
    out = bytearray()
    while True:
        low = value & 0x7F
        value >>= 7
        if value:
            out.append(low | 0x80)
        else:
            out.append(low)
            return bytes(out)


def make_sample(rng):
    count = rng.randint(3, 12)
    records = bytearray()
    for _ in range(count):
        length = rng.choice([0, 1, 4, 9, 20, 50, 90, 127, 128, 150, 200, 300, 400])
        payload = bytes(rng.getrandbits(8) for _ in range(length))
        records += struct.pack("<BB", rng.choice(TYPES), rng.choice([0, 1, 2])) + varint(length) + payload
    total = HEADER.size + len(records) + 4
    header = HEADER.pack(b"XDT3", 3, rng.getrandbits(8), count, 0, rng.getrandbits(32), total)
    body = header + bytes(records)
    return body + struct.pack("<I", zlib.crc32(body))


def generate(n=20, seed=20261024):
    OUT.mkdir(parents=True, exist_ok=True)
    for old in OUT.glob("*.xd3"):
        old.unlink()
    rng = random.Random(seed)
    for i in range(n):
        (OUT / f"sample_{i:02d}.xd3").write_bytes(make_sample(rng))
    return OUT


def truth_fields(data):
    count = struct.unpack_from("<H", data, 6)[0]
    fields = [
        (0, 4, "константа"),
        (4, 5, "константа"),
        (5, 6, "змінне поле"),
        (6, 8, "лічильник"),
        (8, 10, "константа"),
        (10, 14, "змінне поле"),
        (14, 18, "змінне поле"),
    ]
    pos = HEADER.size
    for _ in range(count):
        fields += [(pos, pos + 1, "тип запису"), (pos + 1, pos + 2, "змінне поле")]
        pos += 2
        start, length, shift = pos, 0, 0
        while True:
            b = data[pos]
            pos += 1
            length |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                break
        fields.append((start, pos, "довжина"))
        if length:
            fields.append((pos, pos + length, "дані (блок)"))
        pos += length
    fields.append((pos, pos + 4, "CRC-32"))
    if pos + 4 != len(data):
        raise ValueError("Unexpected XDT3 layout")
    return fields


def read_exact(fp, size):
    data = fp.read(size)
    if len(data) != size:
        raise ValueError("Unexpected end of XDT3 file")
    return data


def read_varint(fp):
    result, shift = 0, 0
    while True:
        b = read_exact(fp, 1)[0]
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result
        shift += 7


def parse_file(fp):
    header = read_exact(fp, HEADER.size)
    magic, version, flags, count, reserved, created, total = HEADER.unpack(header)
    if magic != b"XDT3" or version != 3:
        raise ValueError("Invalid XDT3 header")
    if not 1 <= count <= 100:
        raise ValueError("Invalid record count")

    for _ in range(count):
        kind = read_exact(fp, 1)[0]
        rec_flags = read_exact(fp, 1)[0]
        length = read_varint(fp)
        if length:
            payload = read_exact(fp, length)

    checksum = read_exact(fp, 4)
    if fp.read(1):
        raise ValueError("Trailing bytes")
