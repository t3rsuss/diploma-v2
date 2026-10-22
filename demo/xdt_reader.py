import struct
import e18_context as CTX

CTX.GENERIC.add("read_exact")


def read_exact(fp, size):
    data = fp.read(size)
    if len(data) != size:
        raise ValueError("Unexpected end of XDT1 file")
    return data


def parse_file(fp):
    header = read_exact(fp, 12)
    magic, version, count, flags = struct.unpack("<4sHHI", header)

    if magic != b"XDT1" or version != 1:
        raise ValueError("Invalid XDT1 header")
    if not 1 <= count <= 100:
        raise ValueError("Invalid record count")

    for _ in range(count):
        tag = read_exact(fp, 1)[0]
        length = struct.unpack("<H", read_exact(fp, 2))[0]
        payload = read_exact(fp, length)

    checksum = read_exact(fp, 4)
    if fp.read(1):
        raise ValueError("Trailing bytes")
