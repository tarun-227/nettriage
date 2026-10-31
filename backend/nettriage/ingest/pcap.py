"""Streaming reader for classic libpcap files.

The reader never trusts a length field: a record that claims more than
``limits.max_record_bytes`` is treated as corruption, and the file is read one
record at a time so memory stays flat whatever the file size.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from typing import BinaryIO

from ..config import Limits
from .capture import IngestCounters, RawPacket
from .validate import PCAP_MAGICS

_GLOBAL = {e: struct.Struct(e + "HHiIII") for e in "<>"}
_RECORD = {e: struct.Struct(e + "IIII") for e in "<>"}


def read_pcap(f: BinaryIO, limits: Limits, counters: IngestCounters) -> Iterator[RawPacket]:
    head = f.read(24)
    _fmt, endian, ns_per_unit = PCAP_MAGICS[head[:4]]
    major, minor, _zone, _sigfigs, snaplen, network = _GLOBAL[endian].unpack_from(head, 4)
    if major != 2:
        counters.notes.append(f"Unusual pcap version {major}.{minor}; reading it as 2.4.")
    # The upper bits of the link-type field can carry FCS information.
    linktype = network & 0xFFFF
    counters.link_types.add(linktype)
    frac_limit = 1_000_000 if ns_per_unit == 1_000 else 1_000_000_000
    record = _RECORD[endian]
    max_record = limits.max_record_bytes
    offset = 24
    frame = 0
    bad_fraction_noted = False
    over_snaplen_noted = False

    while True:
        if frame >= limits.max_packets:
            counters.stop(f"Stopped after the packet limit of {limits.max_packets:,} packets.")
            return
        hdr = f.read(16)
        if not hdr:
            return
        if len(hdr) < 16:
            counters.stop(f"File ends inside a packet header at byte {offset:,}; the capture was cut short.")
            return
        ts_sec, ts_frac, incl_len, orig_len = record.unpack(hdr)
        if incl_len > max_record:
            counters.stop(
                f"Packet record at byte {offset:,} claims {incl_len:,} bytes, over the "
                f"{max_record:,}-byte limit. The file is corrupt from this point."
            )
            return
        data = f.read(incl_len)
        frame += 1
        counters.frames = frame
        if len(data) < incl_len:
            counters.skip(frame, "cut off by end of file")
            counters.stop(f"File ends inside packet {frame}; the capture was cut short.")
            return
        if ts_frac >= frac_limit and not bad_fraction_noted:
            counters.notes.append(f"Packet {frame} has an out-of-range timestamp fraction; times may be off.")
            bad_fraction_noted = True
        if snaplen and incl_len > snaplen and not over_snaplen_noted:
            counters.notes.append(
                f"Packet {frame} is longer than the file's snapshot length ({snaplen}); "
                "the writer may be buggy."
            )
            over_snaplen_noted = True
        yield RawPacket(
            frame=frame,
            ts_ns=ts_sec * 1_000_000_000 + ts_frac * ns_per_unit,
            linktype=linktype,
            data=data,
            wire_len=max(orig_len, incl_len),
            offset=offset,
        )
        offset += 16 + incl_len
