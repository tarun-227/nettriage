"""DHCP (BOOTP) decoder. Options are TLVs; every length is checked before use."""

from __future__ import annotations

import socket
import struct

from ..ingest.bytereader import ByteReader
from .model import DHCP
from .text import escape_bytes

MAGIC_COOKIE = b"\x63\x82\x53\x63"
MAX_OPTIONS = 255

DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE, INFORM = range(1, 9)
MSG_NAMES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE",
             8: "INFORM"}

_FIXED = struct.Struct("!BBBBIHH4s4s4s4s16s")

_ntoa = socket.inet_ntoa


def _ip_list(value: bytes) -> list[str]:
    return [_ntoa(value[i:i + 4]) for i in range(0, len(value) - len(value) % 4, 4)][:8]


def decode_dhcp(r: ByteReader) -> DHCP:
    op, htype, hlen, _hops, xid, _secs, _flags, ciaddr, yiaddr, siaddr, giaddr, chaddr = r.unpack(_FIXED)
    r.skip(64 + 128)  # sname and file
    msg = DHCP(
        op=op,
        xid=xid,
        chaddr=chaddr[:6].hex(":") if htype == 1 and hlen == 6 else None,
        ciaddr=_ntoa(ciaddr),
        yiaddr=_ntoa(yiaddr),
        siaddr=_ntoa(siaddr),
        giaddr=_ntoa(giaddr),
    )
    if r.remaining < 4 or r.take(4) != MAGIC_COOKIE:
        return msg  # plain BOOTP, no options
    for _ in range(MAX_OPTIONS):
        if r.remaining == 0:
            break
        code = r.u8()
        if code == 0:
            continue
        if code == 255:
            break
        value = r.take(r.u8())
        if code == 53 and value:
            msg.msg_type = value[0]
        elif code == 54 and len(value) == 4:
            msg.server_id = _ntoa(value)
        elif code == 50 and len(value) == 4:
            msg.requested_ip = _ntoa(value)
        elif code == 1 and len(value) == 4:
            msg.subnet_mask = _ntoa(value)
        elif code == 3:
            msg.routers = _ip_list(value)
        elif code == 6:
            msg.dns_servers = _ip_list(value)
        elif code == 51 and len(value) == 4:
            msg.lease_time = struct.unpack("!I", value)[0]
        elif code == 12:
            msg.hostname = escape_bytes(value, 64)
        elif code == 60:
            msg.vendor_class = escape_bytes(value, 64)
    return msg
