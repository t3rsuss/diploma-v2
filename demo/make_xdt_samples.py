import pathlib
import random
import struct
import zlib

OUT = pathlib.Path(__file__).resolve().parent / "samples_xdt1"


def make_sample(rng):
    count = rng.randint(3, 9)
    body = b"XDT1" + struct.pack("<HHI", 1, count, rng.getrandbits(32))
    for _ in range(count):
        tag = rng.choice([1, 2, 3, 7])
        length = rng.randint(8, 300)
        payload = bytes(rng.getrandbits(8) for _ in range(length))
        body += struct.pack("<BH", tag, length) + payload
    return body + struct.pack("<I", zlib.crc32(body))


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    rng = random.Random(20261022)
    paths = []
    for i in range(20):
        path = OUT / f"sample_{i:02d}.xdt"
        path.write_bytes(make_sample(rng))
        paths.append(path)

    print(f"Created {len(paths)} samples in {OUT}")
    print(f"Total bytes: {sum(p.stat().st_size for p in paths)}")


if __name__ == "__main__":
    main()
