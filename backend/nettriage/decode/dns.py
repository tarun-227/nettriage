"""DNS message decoder.

Defences against hostile messages:
- compression pointers must point strictly backwards, so loops are impossible,
  and the number of jumps is capped as well;
- names are capped at 255 bytes and labels at 63, as RFC 1035 requires;
- record counts from the header are never trusted: we stop at a fixed cap or
  when the bytes run out.
"""

from __future__ import annotations

import socket
import struct

from ..ingest.bytereader import ByteReader, DecodeError, Truncated
from .model import DNS, DNSQuestion, DNSRecord
from .text import escape_dns_label

MAX_POINTER_JUMPS = 32
MAX_NAME_BYTES = 255
MAX_QUESTIONS = 16
MAX_ANSWERS = 64

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_PTR = 12
TYPE_MX = 15
TYPE_AAAA = 28

RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
               33: "SRV", 65: "HTTPS", 255: "ANY"}

_HEADER = struct.Struct("!HHHHHH")
_QTAIL = struct.Struct("!HH")
_RRTAIL = struct.Struct("!HHIH")


def read_name(buf: bytes | memoryview, pos: int, msg_start: int, msg_end: int) -> tuple[str, int]:
    """Read a possibly-compressed name at ``pos``; return (name, offset after it)."""
    labels: list[str] = []
    total = 0
    jumps = 0
    resume: int | None = None
    floor = pos  # every pointer must land strictly before this
    cur = pos
    while True:
        if cur >= msg_end:
            raise Truncated("DNS name runs past the end of the message")
        length = buf[cur]
        kind = length & 0xC0
        if kind == 0xC0:
            if cur + 1 >= msg_end:
                raise Truncated("DNS compression pointer cut short")
            target = msg_start + (((length & 0x3F) << 8) | buf[cur + 1])
            if resume is None:
                resume = cur + 2
            jumps += 1
            if jumps > MAX_POINTER_JUMPS or target >= floor:
                raise DecodeError("DNS compression pointer loop")
            floor = target
            cur = target
            continue
        if kind:
            raise DecodeError("unsupported DNS label type")
        cur += 1
        if length == 0:
            break
        if cur + length > msg_end:
            raise Truncated("DNS label runs past the end of the message")
        total += length + 1
        if total > MAX_NAME_BYTES:
            raise DecodeError("DNS name longer than 255 bytes")
        labels.append(escape_dns_label(bytes(buf[cur:cur + length])))
        cur += length
    name = ".".join(labels) if labels else "."
    return name, resume if resume is not None else cur


def _rdata(r: ByteReader, rtype: int, msg_start: int, msg_end: int) -> str:
    if rtype == TYPE_A and r.remaining == 4:
        return socket.inet_ntoa(r.take(4))
    if rtype == TYPE_AAAA and r.remaining == 16:
        return socket.inet_ntop(socket.AF_INET6, r.take(16))
    if rtype in (TYPE_CNAME, TYPE_NS, TYPE_PTR):
        name, _ = read_name(r.buffer, r.pos, msg_start, msg_end)
        return name
    if rtype == TYPE_MX and r.remaining >= 3:
        pref = r.u16()
        name, _ = read_name(r.buffer, r.pos, msg_start, msg_end)
        return f"{pref} {name}"
    return f"<{r.remaining} bytes>"


def decode_dns(r: ByteReader, multicast: bool = False) -> DNS:
    msg_start, msg_end = r.pos, r.end
    buf = r.buffer
    ident, flags, qdcount, ancount, _nscount, _arcount = r.unpack(_HEADER)
    dns = DNS(
        id=ident,
        qr=bool(flags & 0x8000),
        opcode=(flags >> 11) & 0x0F,
        aa=bool(flags & 0x0400),
        tc=bool(flags & 0x0200),
        rd=bool(flags & 0x0100),
        ra=bool(flags & 0x0080),
        rcode=flags & 0x000F,
        multicast=multicast,
    )
    for _ in range(min(qdcount, MAX_QUESTIONS)):
        name, after = read_name(buf, r.pos, msg_start, msg_end)
        r.seek(after)
        qtype, qclass = r.unpack(_QTAIL)
        dns.questions.append(DNSQuestion(name, qtype, qclass & 0x7FFF))
    for _ in range(min(ancount, MAX_ANSWERS)):
        name, after = read_name(buf, r.pos, msg_start, msg_end)
        r.seek(after)
        rtype, _rclass, ttl, rdlength = r.unpack(_RRTAIL)
        rdata = r.sub(rdlength)
        dns.answers.append(DNSRecord(name, rtype, ttl, _rdata(rdata, rtype, msg_start, msg_end)))
    return dns
