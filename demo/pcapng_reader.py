"""Read the pcapng block envelope; packet bodies remain opaque."""

try:
    import e18_context as CTX
    CTX.GENERIC.add("read_exact")
except ImportError:
    CTX = None

SHB = b"\x0a\x0d\x0d\x0a"


def read_exact(fp, size):
    data = fp.read(size)
    if len(data) != size:
        raise ValueError("Truncated pcapng block")
    return data


def parse_file(fp):
    order = None
    blocks = 0

    while True:
        kind = fp.read(4)
        if not kind:
            break
        if len(kind) != 4:
            raise ValueError("Truncated block type")

        raw_length = read_exact(fp, 4)
        magic_size = 0

        if kind == SHB:
            magic = read_exact(fp, 4)
            if magic == b"\x4d\x3c\x2b\x1a":
                order = "little"
            elif magic == b"\x1a\x2b\x3c\x4d":
                order = "big"
            else:
                raise ValueError("Invalid byte-order magic")
            magic_size = 4
        elif order is None:
            raise ValueError("File must begin with a section header")

        length = int.from_bytes(raw_length, order)
        minimum = 28 if kind == SHB else 12
        if length < minimum or length % 4:
            raise ValueError("Invalid block total length")

        remaining = length - 12 - magic_size
        if remaining:
            read_exact(fp, remaining)

        trailer = int.from_bytes(read_exact(fp, 4), order)
        if trailer != length:
            raise ValueError("Block length trailer mismatch")
        blocks += 1

    if blocks == 0:
        raise ValueError("Empty pcapng file")
    return {"blocks": blocks}
