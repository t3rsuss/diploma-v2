import io
import struct
import wave

import e18_context as CTX
from PIL import Image

from threat_scan import scan


def make_png():
    im = Image.new("RGB", (24, 16), (10, 120, 200))
    buf = io.BytesIO()
    im.save(buf, "PNG")
    return buf.getvalue()


def make_wav():
    buf = io.BytesIO()
    w = wave.open(buf, "wb")
    w.setnchannels(1)
    w.setsampwidth(2)
    w.setframerate(8000)
    w.writeframes(bytes(range(256)) * 4)
    w.close()
    return buf.getvalue()


def pe_stub():
    b = bytearray(160)
    b[0:2] = b"MZ"
    b[0x3C:0x40] = struct.pack("<I", 0x40)
    b[0x40:0x44] = b"PE\x00\x00"
    return bytes(b)


def scan_bytes(fmt, data):
    return scan(data, CTX.run_ctx(fmt, data))


def test_clean_png_is_low():
    assert scan_bytes("png", make_png())["level"] == "low"


def test_png_with_appended_pe_is_high():
    result = scan_bytes("png", make_png() + pe_stub())
    assert result["level"] == "high"
    assert any(h["kind"].startswith("виконуваний файл PE") for r in result["regions"] for h in r["signatures"])


def test_wav_with_junk_chunk_pe_is_high():
    data = make_wav()
    payload = pe_stub()
    chunk = b"JUNK" + struct.pack("<I", len(payload)) + payload
    new = data[:12] + chunk + data[12:]
    new = new[:4] + struct.pack("<I", len(new) - 8) + new[8:]
    assert scan_bytes("wav", new)["level"] == "high"


def test_random_tail_is_mid():
    import random
    rng = random.Random(1)
    tail = bytes(rng.getrandbits(8) for _ in range(512))
    assert scan_bytes("png", make_png() + tail)["level"] == "mid"
