"""Write the broken and hostile captures in samples/malicious/.

Standard library only, so anyone can regenerate them:
    python samples/generate/make_malicious.py            # small files, committed
    python samples/generate/make_malicious.py --large    # adds a 100k-packet SYN flood (not committed)
"""

from __future__ import annotations

import argparse
import random
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "malicious"
GEN = ROOT / "generated"
TS0 = 1_730_390_400  # 2024-10-31 16:00 UTC

GW_MAC = bytes.fromhex("020000000001")
PC_MAC = bytes.fromhex("020000000042")


def pcap_header(linktype: int = 1) -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)


def record(data: bytes, ts: float, incl: int | None = None) -> bytes:
    sec = int(ts)
    usec = int((ts - sec) * 1e6)
    n = len(data) if incl is None else incl
    return struct.pack("<IIII", sec, usec, n, len(data)) + data


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ipv4(src: str, dst: str, proto: int, payload: bytes, ihl: int = 5, ident: int = 1) -> bytes:
    s = bytes(int(x) for x in src.split("."))
    d = bytes(int(x) for x in dst.split("."))
    hdr = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0, s, d)
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    return hdr + payload


def eth(dst: bytes, src: bytes, ethertype: int, payload: bytes) -> bytes:
    return dst + src + struct.pack("!H", ethertype) + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport: int, dport: int, flags: int, seq: int = 0, doff: int = 5) -> bytes:
    return struct.pack("!HHIIHHHH", sport, dport, seq, 0, (doff << 12) | flags, 64240, 0, 0)


def dns_query(ident: int, name: bytes) -> bytes:
    labels = b"".join(bytes([len(p)]) + p for p in name.split(b"."))
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + labels + b"\0" + b"\x00\x01\x00\x01"


def dhcp_request(hostname: bytes, xid: int) -> bytes:
    bootp = bytearray(236)
    bootp[0:4] = bytes([1, 1, 6, 0])
    bootp[4:8] = struct.pack("!I", xid)
    bootp[28:34] = PC_MAC
    opts = b"\x63\x82\x53\x63" + b"\x35\x01\x03" + bytes([12, len(hostname)]) + hostname + b"\xff"
    return bytes(bootp) + opts


def to_pc(payload_ip: bytes) -> bytes:
    return eth(PC_MAC, GW_MAC, 0x0800, payload_ip)


def from_pc(payload_ip: bytes) -> bytes:
    return eth(GW_MAC, PC_MAC, 0x0800, payload_ip)


def normal_frames(n: int) -> list[bytes]:
    return [from_pc(ipv4("10.0.0.42", "10.0.0.1", 17, udp(40000 + i, 53, dns_query(i, b"example.com"))))
            for i in range(n)]


def write(name: str, data: bytes, folder: Path = OUT) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_bytes(data)
    print(f"  {name:28s} {len(data):>10,} bytes")


def make_small() -> None:
    write("not_a_pcap.exe.pcap", b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff" + bytes(200))
    write("empty.pcap", b"")

    good = pcap_header() + b"".join(record(f, TS0 + i * 0.01) for i, f in enumerate(normal_frames(5)))
    write("truncated.pcap", good[:-17])

    huge = pcap_header() + record(normal_frames(1)[0], TS0) + struct.pack("<IIII", TS0, 0, 0xFFFFFFF0, 0xFFFFFFF0)
    write("huge_caplen.pcap", huge + bytes(64))

    shb = struct.pack("<II", 0x0A0D0D0A, 28) + struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + struct.pack("<I", 28)
    idb_body = struct.pack("<HHI", 1, 0, 0)
    idb = struct.pack("<II", 1, 20) + idb_body + struct.pack("<I", 20)
    bad = struct.pack("<II", 6, 13) + bytes(32)
    write("bad_block_len.pcapng", shb + idb + bad)

    frames = []
    frames += normal_frames(2)
    frames.append(from_pc(ipv4("10.0.0.42", "10.0.0.1", 17, udp(1, 2, b"x"), ihl=3)))          # IHL below 5
    frames.append(from_pc(ipv4("10.0.0.42", "93.184.216.34", 6, tcp(40000, 443, 0x02, doff=2))))  # TCP offset 2
    bad_dhcp = bytes(236) + b"\x63\x82\x53\x63\x0c\xff" + b"short"
    frames.append(from_pc(ipv4("0.0.0.0", "255.255.255.255", 17, udp(68, 67, bad_dhcp))))        # option overrun
    frames.append(b"\x01\x02\x03")                                                              # runt frame
    frames.append(bytes(random.Random(7).randrange(256) for _ in range(90)))                    # noise
    frames += normal_frames(2)
    write("corrupt_packets.pcap", pcap_header() + b"".join(record(f, TS0 + i * 0.01) for i, f in enumerate(frames)))

    self_loop = struct.pack("!HHHHHH", 9, 0x8180, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01"
    ping_pong = struct.pack("!HHHHHH", 10, 0x8180, 2, 0, 0, 0) + b"\xc0\x12\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01"
    frames = [to_pc(ipv4("10.0.0.1", "10.0.0.42", 17, udp(53, 40000, self_loop))),
              to_pc(ipv4("10.0.0.1", "10.0.0.42", 17, udp(53, 40001, ping_pong)))] + normal_frames(2)
    write("dns_pointer_loop.pcap", pcap_header() + b"".join(record(f, TS0 + i * 0.01) for i, f in enumerate(frames)))

    names = [b"<script>alert(1)</script>.example.com", b"<img src=x onerror=alert(document.domain)>.test",
             b"\x1b[2J\x1b[31mterminal-takeover.example", b"invoice\xe2\x80\xaefdp.exe.example"]
    frames = [from_pc(ipv4("10.0.0.42", "10.0.0.1", 17, udp(41000 + i, 53, dns_query(100 + i, n))))
              for i, n in enumerate(names)]
    frames.append(eth(b"\xff" * 6, PC_MAC, 0x0800, ipv4("0.0.0.0", "255.255.255.255", 17, udp(
        68, 67, dhcp_request(b"<svg/onload=alert('dhcp')>\x1b]0;owned\x07", 0x1234)))))
    frames.append(eth(b"\xff" * 6, PC_MAC, 0x0800, ipv4("0.0.0.0", "255.255.255.255", 17, udp(
        68, 67, dhcp_request(b'=HYPERLINK("http://evil.example","click")', 0x1235)))))
    write("xss_payloads.pcap", pcap_header() + b"".join(record(f, TS0 + i * 0.5) for i, f in enumerate(frames)))


def make_large() -> None:
    rng = random.Random(1)
    out = [pcap_header()]
    for i in range(100_000):
        src = f"{rng.randrange(1, 224)}.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1, 255)}"
        ip = ipv4(src, "10.0.0.80", 6, tcp(rng.randrange(1024, 65535), 80, 0x02, seq=rng.getrandbits(32)),
                  ident=i & 0xFFFF)
        out.append(record(eth(GW_MAC, PC_MAC, 0x0800, ip), TS0 + i * 0.0001))
    write("syn_flood_100k.pcap", b"".join(out), GEN)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--large", action="store_true", help="also write the 100k-packet SYN flood")
    args = ap.parse_args()
    print("Writing hostile samples:")
    make_small()
    if args.large:
        make_large()
