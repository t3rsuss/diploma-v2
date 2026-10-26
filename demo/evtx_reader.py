import struct

try:
    import e18_context as CTX
    CTX.GENERIC.add("read_exact")
except ImportError:
    CTX = None

FILE_HEADER = 4096
CHUNK = 65536
CHUNK_HEADER = 512


def read_exact(fp, size):
    data = fp.read(size)
    if len(data) != size:
        raise ValueError("Unexpected end of EVTX file")
    return data


def u16(raw):
    return struct.unpack("<H", raw)[0]


def u32(raw):
    return struct.unpack("<I", raw)[0]


def parse_file(fp, max_chunks=None):
    if read_exact(fp, 8) != b"ElfFile\x00":
        raise ValueError("Not an EVTX file")
    read_exact(fp, 8)
    read_exact(fp, 8)
    read_exact(fp, 8)
    header_size = u32(read_exact(fp, 4))
    read_exact(fp, 2)
    read_exact(fp, 2)
    block_size = u16(read_exact(fp, 2))
    declared_chunks = u16(read_exact(fp, 2))
    read_exact(fp, 76)
    read_exact(fp, 4)
    read_exact(fp, 4)
    if header_size != 128 or block_size != FILE_HEADER:
        raise ValueError("Unexpected EVTX header sizes")
    read_exact(fp, FILE_HEADER - 128)

    chunks = unused = records = 0
    while True:
        start = fp.tell()
        signature = fp.read(8)
        if not signature:
            break
        if not any(signature):
            fp.read(CHUNK - len(signature))
            unused += 1
            continue
        if signature != b"ElfChnk\x00":
            raise ValueError("Invalid chunk signature")
        read_exact(fp, 8)
        read_exact(fp, 8)
        read_exact(fp, 8)
        read_exact(fp, 8)
        chunk_header_size = u32(read_exact(fp, 4))
        last_offset = u32(read_exact(fp, 4))
        read_exact(fp, 4)
        read_exact(fp, 4)
        read_exact(fp, 64)
        read_exact(fp, 4)
        read_exact(fp, 4)
        read_exact(fp, 256)
        read_exact(fp, 128)
        if chunk_header_size != 128:
            raise ValueError("Unexpected chunk header size")

        if last_offset >= CHUNK_HEADER:
            while True:
                rec_start = fp.tell() - start
                if read_exact(fp, 4) != b"**\x00\x00":
                    raise ValueError("Invalid record signature")
                size = u32(read_exact(fp, 4))
                if size < 28:
                    raise ValueError("Invalid record size")
                read_exact(fp, 8)
                read_exact(fp, 8)
                read_exact(fp, size - 28)
                if u32(read_exact(fp, 4)) != size:
                    raise ValueError("Record tail mismatch")
                records += 1
                if rec_start >= last_offset:
                    break

        chunks += 1
        slack = CHUNK - (fp.tell() - start)
        if slack < 0:
            raise ValueError("Records overflow chunk")
        fp.read(slack)
        if max_chunks is not None and chunks >= max_chunks:
            break

    return {"declared_chunks": declared_chunks, "chunks": chunks,
            "unused_chunks": unused, "records": records}


def parse_head(fp):
    return parse_file(fp, max_chunks=2)
