"""Author-written pcapng envelope annotation from the public specification."""


def truth(data):
    fields, blocks = [], []
    pos = 0
    order = None

    while pos < len(data):
        if len(data) - pos < 12:
            raise ValueError("Incomplete block envelope")

        section = data[pos:pos + 4] == b"\x0a\x0d\x0d\x0a"
        if section:
            magic = data[pos + 8:pos + 12]
            if magic == b"\x4d\x3c\x2b\x1a":
                order = "little"
            elif magic == b"\x1a\x2b\x3c\x4d":
                order = "big"
            else:
                raise ValueError("Invalid section byte order")
        elif order is None:
            raise ValueError("Missing initial section header")

        size = int.from_bytes(data[pos + 4:pos + 8], order)
        minimum = 28 if section else 12
        end = pos + size
        if size < minimum or size % 4 or end > len(data):
            raise ValueError("Invalid block extent")
        if int.from_bytes(data[end - 4:end], order) != size:
            raise ValueError("Mismatched trailing length")

        fields.extend([
            (pos, pos + 4, "block_type"),
            (pos + 4, pos + 8, "block_length"),
        ])
        body_start = pos + 8
        if section:
            fields.append((body_start, body_start + 4, "byte_order_magic"))
            body_start += 4
        if body_start < end - 4:
            fields.append((body_start, end - 4, "block_body"))
        fields.append((end - 4, end, "block_length_repeat"))

        blocks.append({
            "start": pos,
            "end": end,
            "length_field": [pos + 4, pos + 8],
            "trailer": [end - 4, end],
        })
        pos = end

    if not blocks:
        raise ValueError("Empty pcapng file")
    return fields, blocks
