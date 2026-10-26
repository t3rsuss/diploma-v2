r"""Extract unique DNS messages (UDP port 53) from pktmon pcapng files.

Capture (elevated PowerShell), see Microsoft pktmon documentation:
  pktmon filter add -p 53
  pktmon start --capture --pkt-size 0 --file-name <dir>/x.etl
  ... generate DNS traffic ...
  pktmon stop
  pktmon etl2pcap <dir>/x.etl --out <dir>/x.pcapng

Observed on the author machine: frames are declared as Ethernet but start with
a raw IPv4 header, and every packet is logged several times (components), so
duplicates are removed by bytes.
"""
import hashlib
import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "data/corpus/pcapng"
OUT = ROOT / "data/corpus/dns"


def frames(raw):
    pos = 0
    while pos + 12 <= len(raw):
        btype, blen = struct.unpack_from("<II", raw, pos)
        if blen < 12 or pos + blen > len(raw) or struct.unpack_from("<I", raw, pos + blen - 4)[0] != blen:
            raise ValueError(f"bad pcapng block at {pos}")
        if btype == 6:
            body = raw[pos + 8:pos + blen - 4]
            cap = struct.unpack_from("<I", body, 12)[0]
            yield body[20:20 + cap]
        pos += blen


def locate_ip(frame):
    if (len(frame) >= 20 and frame[0] >> 4 == 4 and (frame[0] & 15) >= 5
            and struct.unpack_from(">H", frame, 2)[0] <= len(frame)
            and frame[9] in (1, 6, 17)):
        return 4, 0
    if len(frame) >= 40 and frame[0] >> 4 == 6:
        return 6, 0
    if len(frame) >= 14:
        et = struct.unpack_from(">H", frame, 12)[0]
        off = 14
        if et == 0x8100 and len(frame) >= 18:
            et = struct.unpack_from(">H", frame, 16)[0]
            off = 18
        if et == 0x0800:
            return 4, off
        if et == 0x86DD:
            return 6, off
    return None


def dns_payload(frame):
    loc = locate_ip(frame)
    if loc is None:
        return None
    ver, off = loc
    if ver == 4:
        nxt, udp_at = frame[off + 9], off + (frame[off] & 15) * 4
    else:
        nxt, udp_at = frame[off + 6], off + 40
    if nxt != 17 or len(frame) < udp_at + 8:
        return None
    sport, dport, ulen, _ = struct.unpack_from(">HHHH", frame, udp_at)
    payload = frame[udp_at + 8:udp_at + ulen]
    if (sport == 53 or dport == 53) and len(payload) >= 12:
        return payload
    return None


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    unique = {}
    total = 0
    for path in sorted(SRC.glob("*.pcapng")):
        for frame in frames(path.read_bytes()):
            payload = dns_payload(frame)
            if payload:
                total += 1
                unique.setdefault(payload, None)
    for m in unique:
        (OUT / (hashlib.sha256(m).hexdigest()[:12] + ".dns")).write_bytes(m)
    resp = sum(1 for m in unique if m[2] & 0x80)
    print(f"messages: {total} | unique: {len(unique)} | responses: {resp} | queries: {len(unique) - resp}")


if __name__ == "__main__":
    main()
