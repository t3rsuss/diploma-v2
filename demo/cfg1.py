import json
import pathlib
import random
import struct

import e18_context as CTX

CTX.GENERIC.add("read_exact")

OUT = pathlib.Path(__file__).resolve().parent / "samples_cfg1"
LABELS = pathlib.Path(__file__).resolve().parent / "cfg1_labels.json"
HEADER = struct.Struct("<4sBHB")
WORDS = ["alpha", "bravo", "delta", "echo", "gamma", "omega", "sigma", "node", "relay", "cache"]


def text(rng, n):
    out = []
    while sum(len(w) + 1 for w in out) < n:
        out.append(rng.choice(WORDS))
    return " ".join(out).encode()[:n]


def fake_pe(rng, size):
    body = bytearray(rng.getrandbits(8) for _ in range(size))
    body[0:2] = b"MZ"
    e = 0x80
    body[0x3C:0x40] = struct.pack("<I", e)
    body[e:e + 4] = b"PE\x00\x00"
    return bytes(body)


def record(kind, payload):
    return struct.pack("<BH", kind, len(payload)) + payload


def make_sample(rng, malicious):
    records, label = [], {"malicious": malicious, "kind": "benign", "block": None}
    for _ in range(rng.randint(3, 6)):
        k = rng.choice([1, 2, 3, 4, 5])
        if k == 1:
            payload = f"node-{rng.randint(1, 99)}.example.org".encode()
        elif k == 2:
            payload = struct.pack("<H", rng.choice([80, 443, 8080, 8443]))
        elif k == 3:
            payload = struct.pack("<I", rng.randint(10, 3600))
        elif k == 4:
            payload = f"https://example.org/{text(rng, 8).decode()}".encode()
        else:
            payload = text(rng, rng.choice([rng.randint(20, 120), rng.randint(1200, 2500)]))
        records.append(record(k, payload))

    module = None
    if malicious:
        kind = rng.choice(["pe", "xor_pe", "encrypted"])
        size = rng.randint(300, 700)
        if kind == "pe":
            module = fake_pe(rng, size)
        elif kind == "xor_pe":
            key = rng.randint(1, 255)
            module = bytes(b ^ key for b in fake_pe(rng, size))
        else:
            module = bytes(rng.getrandbits(8) for _ in range(size))
        label["kind"] = kind
    elif rng.random() < 0.4:
        import zlib
        raw = text(rng, rng.randint(1500, 3000))
        module = zlib.compress(raw) if rng.random() < 0.5 else raw
        label["kind"] = "benign_module"

    if module is not None:
        pos = rng.randint(0, len(records))
        records.insert(pos, record(0x7F, module))

    body = bytearray()
    start_of_module = None
    for rec in records:
        if rec[0] == 0x7F and module is not None and rec[3:] == module:
            start_of_module = HEADER.size + len(body) + 3
        body += rec
    if malicious and start_of_module is not None:
        label["block"] = [start_of_module, start_of_module + len(module)]
    data = HEADER.pack(b"CFG1", 1, len(records), rng.getrandbits(8)) + bytes(body)
    return data, label


def generate(n_benign=20, n_mal=20, seed=20261025):
    OUT.mkdir(parents=True, exist_ok=True)
    for old in OUT.glob("*.cfg"):
        old.unlink()
    rng = random.Random(seed)
    labels = {}
    for i in range(n_benign + n_mal):
        mal = i >= n_benign
        data, label = make_sample(rng, mal)
        name = f"{'mal' if mal else 'ok'}_{i:02d}.cfg"
        (OUT / name).write_bytes(data)
        labels[name] = label
    LABELS.write_text(json.dumps(labels, ensure_ascii=False, indent=1), encoding="utf-8")
    return OUT, labels


def truth_fields(data):
    count = struct.unpack_from("<H", data, 5)[0]
    fields = [(0, 4, "константа"), (4, 5, "константа"), (5, 7, "лічильник"), (7, 8, "змінне поле")]
    pos = HEADER.size
    for _ in range(count):
        length = struct.unpack_from("<H", data, pos + 1)[0]
        fields += [(pos, pos + 1, "тип запису"), (pos + 1, pos + 3, "довжина"),
                   (pos + 3, pos + 3 + length, "дані (блок)")]
        pos += 3 + length
    if pos != len(data):
        raise ValueError("Unexpected CFG1 layout")
    return fields


def read_exact(fp, size):
    data = fp.read(size)
    if len(data) != size:
        raise ValueError("Unexpected end of CFG1 file")
    return data


def parse_file(fp):
    magic, version, count, flags = HEADER.unpack(read_exact(fp, HEADER.size))
    if magic != b"CFG1" or version != 1:
        raise ValueError("Invalid CFG1 header")
    for _ in range(count):
        kind = read_exact(fp, 1)[0]
        length = struct.unpack("<H", read_exact(fp, 2))[0]
        payload = read_exact(fp, length)
    if fp.read(1):
        raise ValueError("Trailing bytes")
