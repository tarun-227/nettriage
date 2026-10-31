"""Write packets to a nanosecond-resolution pcap, for evidence.pcap downloads."""

from __future__ import annotations

import struct
from collections.abc import Iterable

NS_MAGIC_LE = 0xA1B23C4D

_GLOBAL = struct.Struct("<IHHiIII")
_RECORD = struct.Struct("<IIII")


def pcap_bytes(packets: Iterable[tuple[int, bytes, int]], linktype: int, snaplen: int = 262_144) -> bytes:
    """``packets`` yields (ts_ns, data, wire_len)."""
    out = [_GLOBAL.pack(NS_MAGIC_LE, 2, 4, 0, 0, snaplen, linktype)]
    for ts_ns, data, wire_len in packets:
        sec, ns = divmod(ts_ns, 1_000_000_000)
        out.append(_RECORD.pack(sec & 0xFFFFFFFF, ns, len(data), max(wire_len, len(data))))
        out.append(data)
    return b"".join(out)
