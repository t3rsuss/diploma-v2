import pathlib
import random
import struct
import zlib

import e18_context as CTX

CTX.GENERIC.add("read_exact")

OUT = pathlib.Path(__file__).resolve().parent / "samples_xdt2"
TAGS = [0x10, 0x20, 0x30, 0x41]


def make_sample(rng):
    count = rng.randint(3, 12)
    body = b"XDT2" + struct.pack(">HHII", 2, rng.getrandbits(16), count, rng.getrandbits(32))
    for _ in range(count):
        tag = rng.choice(TAGS)
        length = rng.choice([0, 1, 2, 3, 5, 8, 16, 33, 64, 100, 180, 255, 300, 400])
        payload = bytes(rng.getrandbits(8) for _ in range(length))
        body += struct.pack(">HI", tag, length) + payload
    body += b"END!"
    return body + struct.pack(">I", zlib.crc32(body))


def generate(n=20, seed=20261023):
    OUT.mkdir(parents=True, exist_ok=True)
    for old in OUT.glob("*.xd2"):
        old.unlink()
    rng = random.Random(seed)
    for i in range(n):
        (OUT / f"sample_{i:02d}.xd2").write_bytes(make_sample(rng))
    return OUT


def truth_fields(data):
    count = struct.unpack_from(">I", data, 8)[0]
    fields = [
        (0, 4, "константа"),
        (4, 6, "константа"),
        (6, 8, "змінне поле"),
        (8, 12, "лічильник"),
        (12, 16, "змінне поле"),
    ]
    pos = 16
    for _ in range(count):
        length = struct.unpack_from(">I", data, pos + 2)[0]
        fields += [(pos, pos + 2, "тип запису"), (pos + 2, pos + 6, "довжина")]
        if length:
            fields.append((pos + 6, pos + 6 + length, "дані (блок)"))
        pos += 6 + length
    fields += [(pos, pos + 4, "константа"), (pos + 4, pos + 8, "CRC-32")]
    if pos + 8 != len(data):
        raise ValueError("Unexpected XDT2 layout")
    return fields


def read_exact(fp, size):
    data = fp.read(size)
    if len(data) != size:
        raise ValueError("Unexpected end of XDT2 file")
    return data


def parse_file(fp):
    header = read_exact(fp, 16)
    magic, version, flags, count, created = struct.unpack(">4sHHII", header)
    if magic != b"XDT2" or version != 2:
        raise ValueError("Invalid XDT2 header")
    if not 1 <= count <= 100:
        raise ValueError("Invalid record count")

    for _ in range(count):
        tag = struct.unpack(">H", read_exact(fp, 2))[0]
        length = struct.unpack(">I", read_exact(fp, 4))[0]
        if length:
            payload = read_exact(fp, length)

    footer = read_exact(fp, 4)
    checksum = read_exact(fp, 4)
    if footer != b"END!" or fp.read(1):
        raise ValueError("Invalid footer")
