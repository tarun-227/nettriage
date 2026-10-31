"""Streaming reader for pcapng files.

Each block is read whole (bounded by ``limits.max_block_bytes``), its trailing
length must match its leading length, and every field inside it is read
through ``ByteReader``. Frame numbers count every packet block, including ones
we skip, so they line up with Wireshark.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from typing import BinaryIO

from ..config import Limits
from .bytereader import ByteReader, DecodeError
from .capture import IngestCounters, RawPacket

SHB = b"\x0a\x0d\x0d\x0a"
BOM_LE = b"\x4d\x3c\x2b\x1a"
BOM_BE = b"\x1a\x2b\x3c\x4d"

BT_IDB = 0x00000001
BT_PB = 0x00000002     # obsolete Packet Block
BT_SPB = 0x00000003
BT_EPB = 0x00000006

_EPB = {e: struct.Struct(e + "IIIII") for e in "<>"}
_PB = {e: struct.Struct(e + "HHIIII") for e in "<>"}
_SPB = {e: struct.Struct(e + "I") for e in "<>"}

OPT_END = 0
OPT_IF_TSRESOL = 9
OPT_IF_TSOFFSET = 14


@dataclass(slots=True)
class _Interface:
    linktype: int
    snaplen: int
    resol: int = 6          # if_tsresol byte; default is microseconds
    offset_s: int = 0       # if_tsoffset, seconds


def _to_ns(units: int, resol: int) -> int:
    exp = resol & 0x7F
    if resol & 0x80:
        return (units * 1_000_000_000) >> exp
    if exp <= 9:
        return units * 10 ** (9 - exp)
    return units // 10 ** (exp - 9)


def _parse_idb(body: bytes, endian: str, counters: IngestCounters) -> _Interface:
    r = ByteReader(body)
    linktype, _reserved, snaplen = r.unpack(struct.Struct(endian + "HHI"))
    iface = _Interface(linktype=linktype, snaplen=snaplen)
    opt_hdr = struct.Struct(endian + "HH")
    # Options are a list of (code, length, value padded to 4 bytes).
    for _ in range(256):
        if r.remaining < 4:
            break
        code, length = r.unpack(opt_hdr)
        if code == OPT_END:
            break
        value = r.take(length)
        r.skip(min((-length) % 4, r.remaining))
        if code == OPT_IF_TSRESOL and length >= 1:
            resol = value[0]
            # Anything finer than attoseconds is nonsense; keep the default.
            if (resol & 0x7F) <= (60 if resol & 0x80 else 18):
                iface.resol = resol
            else:
                counters.notes.append(f"Ignored an invalid timestamp resolution ({resol}) on an interface.")
        elif code == OPT_IF_TSOFFSET and length >= 8:
            iface.offset_s = struct.unpack(endian + "q", value[:8])[0]
    return iface


def read_pcapng(f: BinaryIO, limits: Limits, counters: IngestCounters) -> Iterator[RawPacket]:
    endian: str | None = None
    interfaces: list[_Interface] = []
    offset = 0
    frame = 0
    max_block = limits.max_block_bytes
    max_record = limits.max_record_bytes
    last_ts_ns = 0

    while True:
        if frame >= limits.max_packets:
            counters.stop(f"Stopped after the packet limit of {limits.max_packets:,} packets.")
            return
        head = f.read(8)
        if not head:
            return
        if len(head) < 8:
            counters.stop(f"File ends inside a block header at byte {offset:,}; the capture was cut short.")
            return

        if head[:4] == SHB:
            bom = f.read(4)
            if bom == BOM_LE:
                endian = "<"
            elif bom == BOM_BE:
                endian = ">"
            else:
                counters.stop(f"Section header at byte {offset:,} has an invalid byte-order magic.")
                return
            btype = None
            total = struct.unpack(endian + "I", head[4:8])[0]
            consumed = 12
            interfaces = []  # a new section starts a new interface list
        else:
            if endian is None:
                counters.stop("File does not start with a pcapng section header.")
                return
            btype, total = struct.unpack(endian + "II", head)
            consumed = 8

        if total < 12 or total % 4 or total > max_block or total < consumed + 4:
            counters.stop(
                f"Block at byte {offset:,} has an invalid length ({total:,}). "
                "The file is corrupt from this point."
            )
            return
        body_len = total - consumed - 4
        body = f.read(body_len)
        trailer = f.read(4)
        if len(body) < body_len or len(trailer) < 4:
            counters.stop(f"File ends inside the block at byte {offset:,}; the capture was cut short.")
            return
        if struct.unpack(endian + "I", trailer)[0] != total:
            counters.stop(
                f"Block at byte {offset:,} has mismatched leading and trailing lengths. "
                "The file is corrupt from this point."
            )
            return

        block_offset = offset
        offset += total

        if btype is None:
            continue  # section header body: version and options, nothing we need
        if btype == BT_IDB:
            try:
                iface = _parse_idb(body, endian, counters)
            except DecodeError as e:
                counters.notes.append(f"Interface description at byte {block_offset:,} is malformed: {e}")
                iface = _Interface(linktype=0xFFFF, snaplen=0)
            interfaces.append(iface)
            counters.link_types.add(iface.linktype)
            continue
        if btype not in (BT_EPB, BT_SPB, BT_PB):
            continue  # name resolution, statistics, decryption secrets, custom blocks

        frame += 1
        counters.frames = frame
        try:
            r = ByteReader(body)
            if btype == BT_EPB:
                if_id, ts_hi, ts_lo, caplen, origlen = r.unpack(_EPB[endian])
            elif btype == BT_PB:
                if_id, _drops, ts_hi, ts_lo, caplen, origlen = r.unpack(_PB[endian])
            else:
                if_id, ts_hi, ts_lo = 0, None, None
                (origlen,) = r.unpack(_SPB[endian])
                caplen = min(origlen, r.remaining)
            if if_id >= len(interfaces):
                counters.skip(frame, "packet refers to an undefined interface")
                continue
            iface = interfaces[if_id]
            if btype == BT_SPB and iface.snaplen:
                caplen = min(caplen, iface.snaplen)
            if caplen > max_record:
                counters.skip(frame, "packet larger than the record size limit")
                continue
            data = r.take(caplen)
        except DecodeError:
            counters.skip(frame, "packet length runs past the end of its block")
            continue

        if ts_hi is None:
            ts_ns = last_ts_ns  # simple packet blocks carry no timestamp
        else:
            ts_ns = _to_ns((ts_hi << 32) | ts_lo, iface.resol) + iface.offset_s * 1_000_000_000
            last_ts_ns = ts_ns
        yield RawPacket(
            frame=frame,
            ts_ns=ts_ns,
            linktype=iface.linktype,
            data=data,
            wire_len=max(origlen, caplen),
            offset=block_offset,
        )
