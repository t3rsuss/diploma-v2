import struct

try:
    import e18_context as CTX
    CTX.GENERIC.add("read_exact")
except ImportError:
    CTX = None


def read_exact(fp, size):
    data = fp.read(size)
    if len(data) != size:
        raise ValueError("Unexpected end of DNS message")
    return data


def u16(raw):
    return struct.unpack(">H", raw)[0]


def read_name(fp):
    while True:
        length = read_exact(fp, 1)[0]
        if length == 0:
            return
        if length & 0xC0 == 0xC0:
            read_exact(fp, 1)
            return
        if length & 0xC0:
            raise ValueError("Unsupported label type")
        read_exact(fp, length)


def read_record(fp):
    read_name(fp)
    read_exact(fp, 2)
    read_exact(fp, 2)
    read_exact(fp, 4)
    rdlength = u16(read_exact(fp, 2))
    read_exact(fp, rdlength)


def parse_file(fp):
    read_exact(fp, 2)
    read_exact(fp, 2)
    qdcount = u16(read_exact(fp, 2))
    ancount = u16(read_exact(fp, 2))
    nscount = u16(read_exact(fp, 2))
    arcount = u16(read_exact(fp, 2))
    for _ in range(qdcount):
        read_name(fp)
        read_exact(fp, 2)
        read_exact(fp, 2)
    for _ in range(ancount):
        read_record(fp)
    for _ in range(nscount):
        read_record(fp)
    for _ in range(arcount):
        read_record(fp)
    if fp.read(1):
        raise ValueError("Trailing bytes")
