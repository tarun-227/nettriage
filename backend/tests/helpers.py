"""Builders for hand-made captures, including deliberately broken ones."""

from __future__ import annotations

import io
import struct

from nettriage.config import Limits
from nettriage.decode.model import Packet
from nettriage.ingest.capture import IngestCounters
from nettriage.ingest.stream import stream_packets

TS0 = 1_700_000_000


def pcap_header(linktype: int = 1, endian: str = "<", nanos: bool = False, snaplen: int = 65535) -> bytes:
    magic = 0xA1B23C4D if nanos else 0xA1B2C3D4
    return struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, snaplen, linktype)


def pcap_record(data: bytes, ts: float, endian: str = "<", nanos: bool = False,
                incl_len: int | None = None, wire_len: int | None = None) -> bytes:
    sec = int(ts)
    frac = round((ts - sec) * (1e9 if nanos else 1e6))
    incl = len(data) if incl_len is None else incl_len
    wire = len(data) if wire_len is None else wire_len
    return struct.pack(endian + "IIII", sec, frac, incl, wire) + data


def build_pcap(frames: list[bytes], linktype: int = 1, endian: str = "<", nanos: bool = False,
               step: float = 0.001) -> bytes:
    out = [pcap_header(linktype, endian, nanos)]
    for i, data in enumerate(frames):
        out.append(pcap_record(data, TS0 + i * step, endian, nanos))
    return b"".join(out)


def pcapng_block(btype: int, body: bytes, endian: str = "<", total: int | None = None,
                 trailer: int | None = None) -> bytes:
    pad = (-len(body)) % 4
    length = 12 + len(body) + pad if total is None else total
    tail = length if trailer is None else trailer
    return struct.pack(endian + "II", btype, length) + body + b"\0" * pad + struct.pack(endian + "I", tail)


def pcapng_shb(endian: str = "<") -> bytes:
    body = struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1)
    return pcapng_block(0x0A0D0D0A, body, endian)


def pcapng_idb(linktype: int = 1, endian: str = "<", tsresol: int | None = None) -> bytes:
    body = struct.pack(endian + "HHI", linktype, 0, 0)
    if tsresol is not None:
        body += struct.pack(endian + "HH", 9, 1) + bytes([tsresol]) + b"\0\0\0"
        body += struct.pack(endian + "HH", 0, 0)
    return pcapng_block(1, body, endian)


def pcapng_epb(data: bytes, ts_units: int, if_id: int = 0, endian: str = "<",
               caplen: int | None = None) -> bytes:
    cl = len(data) if caplen is None else caplen
    body = struct.pack(endian + "IIIII", if_id, ts_units >> 32, ts_units & 0xFFFFFFFF, cl, len(data)) + data
    return pcapng_block(6, body, endian)


def build_pcapng(frames: list[bytes], endian: str = "<", tsresol: int | None = None) -> bytes:
    out = [pcapng_shb(endian), pcapng_idb(1, endian, tsresol)]
    per_sec = 10 ** (tsresol if tsresol is not None else 6)
    for i, data in enumerate(frames):
        out.append(pcapng_epb(data, (TS0 + i) * per_sec, endian=endian))
    return b"".join(out)


def read_all(data: bytes, limits: Limits | None = None) -> tuple[list[Packet], IngestCounters]:
    limits = limits or Limits()
    counters = IngestCounters(limits=limits)
    packets = list(stream_packets(io.BytesIO(data), limits, counters))
    return packets, counters
