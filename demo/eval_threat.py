import json
import pathlib
import random
import struct
import sys
import zipfile
from collections import Counter
from io import BytesIO

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments"))

PER_CLASS, SEED = 30, 42


def stub_pe(rng, n=160):
    b = bytearray(rng.getrandbits(8) for _ in range(n))
    b[0:2] = b"MZ"
    b[0x3C:0x40] = struct.pack("<I", 0x40)
    b[0x40:0x44] = b"PE\x00\x00"
    return bytes(b)


def stub_elf(rng, n=160):
    b = bytearray(rng.getrandbits(8) for _ in range(n))
    b[0:7] = b"\x7fELF\x02\x01\x01"
    return bytes(b)


def stub_zip():
    buf = BytesIO()
    z = zipfile.ZipFile(buf, "w")
    z.writestr("a.txt", "hello" * 20)
    z.close()
    return buf.getvalue()


def wav_insert(data, payload):
    chunk = b"JUNK" + struct.pack("<I", len(payload)) + payload + (b"\x00" if len(payload) % 2 else b"")
    new = data[:12] + chunk + data[12:]
    return new[:4] + struct.pack("<I", len(new) - 8) + new[8:]


def variants(fmt, base, rng):
    out = {
        "clean": base,
        "tail_pe": base + stub_pe(rng),
        "tail_elf": base + stub_elf(rng),
        "tail_zip": base + stub_zip(),
        "tail_random": base + bytes(rng.getrandbits(8) for _ in range(512)),
    }
    if fmt == "wav":
        out["junk_pe"] = wav_insert(base, stub_pe(rng))
    return out


def main():
    import trace_lib as T
    import e18_context as CTX
    from threat_scan import scan

    files = T.collect_files()
    rng = random.Random(SEED)
    lines = [f"{'формат':7s}{'варіант':13s}{'файлів':>7s}{'low':>6s}{'mid':>6s}{'high':>6s}{'помилок':>9s}"]
    table = []
    for fmt in ("png", "wav"):
        lst = sorted(files[fmt])
        rng.shuffle(lst)
        bases = []
        for p in lst:
            if len(bases) >= PER_CLASS:
                break
            try:
                if not (1024 <= p.stat().st_size <= 150_000):
                    continue
                data = p.read_bytes()
                CTX.run_ctx(fmt, data)
            except Exception:
                continue
            bases.append(data)
        counters = {}
        for base in bases:
            for name, data in variants(fmt, base, rng).items():
                c = counters.setdefault(name, Counter())
                try:
                    c[scan(data, CTX.run_ctx(fmt, data))["level"]] += 1
                except Exception:
                    c["error"] += 1
        for name, c in counters.items():
            n = sum(c.values())
            table.append({"format": fmt, "variant": name, "files": n, **dict(c)})
            lines.append(
                f"{fmt:7s}{name:13s}{n:7d}{c['low']:6d}{c['mid']:6d}{c['high']:6d}{c['error']:9d}"
            )

    text = "\n".join(lines)
    print(text)
    out = ROOT / "results"
    out.mkdir(exist_ok=True)
    (out / "eval_threat.txt").write_text(text + "\n", encoding="utf-8")
    (out / "eval_threat.json").write_text(json.dumps(table, ensure_ascii=False, indent=2), encoding="utf-8")
    print("Saved: results/eval_threat.txt, results/eval_threat.json")


if __name__ == "__main__":
    main()
