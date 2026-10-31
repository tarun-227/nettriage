"""Link, network and transport layer decoders.

Each function reads from a ByteReader and either returns a decoded header or
raises DecodeError. None of them trusts a length field without checking it
against the bytes actually present.
"""

from __future__ import annotations

import socket
import struct

from ..ingest.bytereader import ByteReader, DecodeError
from .model import (
    ARP,
    ETH_IPV4,
    ETH_IPV6,
    ICMP,
    IP,
    PROTO_ICMP,
    PROTO_ICMPV6,
    PROTO_TCP,
    PROTO_UDP,
    TCP,
    UDP,
    Link,
)

LINKTYPE_NAMES = {
    0: "BSD loopback",
    1: "Ethernet",
    12: "Raw IP",
    14: "Raw IP",
    101: "Raw IP",
    108: "OpenBSD loopback",
    113: "Linux cooked (SLL)",
    228: "Raw IPv4",
    229: "Raw IPv6",
    276: "Linux cooked (SLL2)",
}
SUPPORTED_LINKTYPES = set(LINKTYPE_NAMES)

_VLAN_TYPES = (0x8100, 0x88A8, 0x9100)
_MAX_VLAN_TAGS = 2
_MAX_IPV6_EXT_HEADERS = 8

_ETH = struct.Struct("!6s6sH")
_VLAN = struct.Struct("!HH")
_SLL = struct.Struct("!HHH8sH")
_SLL2 = struct.Struct("!HHIHBB8s")
_IPV4 = struct.Struct("!BBHHHBBH4s4s")
_IPV6 = struct.Struct("!IHBB16s16s")
_TCP = struct.Struct("!HHIIHHHH")
_UDP = struct.Struct("!HHHH")
_ICMP = struct.Struct("!BBH")
_ARP = struct.Struct("!HHBBH")

_inet_ntoa = socket.inet_ntoa


def _ntop6(b: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6, b)


def mac_str(b: bytes) -> str:
    return b.hex(":")


def linktype_name(linktype: int) -> str:
    return LINKTYPE_NAMES.get(linktype, f"link type {linktype}")


def _ethertype_from_version(r: ByteReader) -> int:
    version = r.peek_u8() >> 4
    if version == 4:
        return ETH_IPV4
    if version == 6:
        return ETH_IPV6
    raise DecodeError(f"raw IP packet with version {version}")


def decode_link(linktype: int, r: ByteReader) -> Link:
    """Return the link header; ``r`` is left at the start of the network layer."""
    if linktype == 1:
        dst, src, ethertype = r.unpack(_ETH)
        vlan = None
        for _ in range(_MAX_VLAN_TAGS):
            if ethertype not in _VLAN_TYPES:
                break
            tci, ethertype = r.unpack(_VLAN)
            if vlan is None:
                vlan = tci & 0x0FFF
        return Link(mac_str(src), mac_str(dst), ethertype, vlan)
    if linktype == 113:
        _pkttype, hatype, halen, addr, proto = r.unpack(_SLL)
        src = mac_str(addr[:6]) if hatype == 1 and halen == 6 else None
        return Link(src, None, proto)
    if linktype == 276:
        proto, _res, _ifindex, hatype, _pkttype, halen, addr = r.unpack(_SLL2)
        src = mac_str(addr[:6]) if hatype == 1 and halen == 6 else None
        return Link(src, None, proto)
    if linktype in (12, 14, 101, 228, 229):
        return Link(None, None, _ethertype_from_version(r))
    if linktype in (0, 108):
        family_bytes = r.take(4)
        le = struct.unpack("<I", family_bytes)[0]
        be = struct.unpack(">I", family_bytes)[0]
        # LOOP is network order; NULL is the capturing host's order, which we
        # cannot know, so fall back to the other order if the value is absurd.
        family = be if linktype == 108 else le
        if family > 0xFFFF:
            family = le if linktype == 108 else be
        if family == 2:
            return Link(None, None, ETH_IPV4)
        if family in (10, 24, 28, 30):
            return Link(None, None, ETH_IPV6)
        return Link(None, None, 0)
    raise DecodeError(f"unsupported link type {linktype}")


def decode_ipv4(r: ByteReader) -> tuple[IP, ByteReader]:
    vihl, _tos, total_len, ident, flags_frag, ttl, proto, _csum, src, dst = r.unpack(_IPV4)
    if vihl >> 4 != 4:
        raise DecodeError(f"IPv4 header with version {vihl >> 4}")
    ihl = (vihl & 0x0F) * 4
    if ihl < 20:
        raise DecodeError(f"IPv4 header length {ihl} is below the minimum of 20")
    r.skip(ihl - 20)
    if total_len == 0:
        # Captured on the sending host with segmentation offload: the length
        # is filled in later by the NIC, so use what was captured.
        total_len = ihl + r.remaining
    if total_len < ihl:
        raise DecodeError(f"IPv4 total length {total_len} is smaller than its header ({ihl})")
    payload_len = total_len - ihl
    # Ethernet pads short frames, and snaplen may cut long ones: take the smaller.
    payload = ByteReader(r.buffer, r.pos, r.pos + min(payload_len, r.remaining))
    ip = IP(
        version=4,
        src=_inet_ntoa(src),
        dst=_inet_ntoa(dst),
        proto=proto,
        ttl=ttl,
        ident=ident,
        df=bool(flags_frag & 0x4000),
        mf=bool(flags_frag & 0x2000),
        frag_offset=(flags_frag & 0x1FFF) * 8,
        header_len=ihl,
        payload_len=payload_len,
    )
    return ip, payload


def decode_ipv6(r: ByteReader) -> tuple[IP, ByteReader]:
    vtcfl, plen, next_header, hop_limit, src, dst = r.unpack(_IPV6)
    if vtcfl >> 28 != 6:
        raise DecodeError(f"IPv6 header with version {vtcfl >> 28}")
    if plen == 0:
        plen = r.remaining  # jumbogram or offload
    end = r.pos + min(plen, r.remaining)
    body = ByteReader(r.buffer, r.pos, end)
    frag_offset = 0
    mf = False
    ident = None
    ext_len = 0
    for _ in range(_MAX_IPV6_EXT_HEADERS + 1):
        if next_header in (0, 43, 60):  # hop-by-hop, routing, destination options
            nh, hlen = body.u8(), body.u8()
            body.skip((hlen + 1) * 8 - 2)
            ext_len += (hlen + 1) * 8
            next_header = nh
        elif next_header == 44:  # fragment
            nh = body.u8()
            body.skip(1)
            fo = body.u16()
            ident = body.u32()
            frag_offset = (fo >> 3) * 8
            mf = bool(fo & 1)
            ext_len += 8
            next_header = nh
        elif next_header == 51:  # authentication header
            nh, alen = body.u8(), body.u8()
            body.skip((alen + 2) * 4 - 2)
            ext_len += (alen + 2) * 4
            next_header = nh
        else:
            break
    else:
        raise DecodeError("too many IPv6 extension headers")
    ip = IP(
        version=6,
        src=_ntop6(src),
        dst=_ntop6(dst),
        proto=next_header,
        ttl=hop_limit,
        ident=ident,
        df=False,
        mf=mf,
        frag_offset=frag_offset,
        header_len=40 + ext_len,
        payload_len=max(0, plen - ext_len),
    )
    return ip, body


def _tcp_options(r: ByteReader, tcp: TCP) -> None:
    # Malformed options are common in the wild and harmless to us: stop quietly.
    for _ in range(40):
        if r.remaining == 0:
            return
        kind = r.u8()
        if kind == 0:
            return
        if kind == 1:
            continue
        if r.remaining == 0:
            return
        length = r.u8()
        if length < 2 or length - 2 > r.remaining:
            return
        value = r.take(length - 2)
        if kind == 2 and length == 4:
            tcp.mss = struct.unpack("!H", value)[0]
        elif kind == 3 and length == 3:
            tcp.wscale = value[0]
        elif kind == 4:
            tcp.sack_ok = True


def decode_tcp(r: ByteReader, declared_len: int) -> TCP:
    sport, dport, seq, ack, off_flags, window, _csum, _urg = r.unpack(_TCP)
    doff = (off_flags >> 12) * 4
    if doff < 20:
        raise DecodeError(f"TCP data offset {doff} is below the minimum of 20")
    if doff > declared_len:
        raise DecodeError(f"TCP header ({doff} bytes) is longer than its IP payload ({declared_len})")
    tcp = TCP(
        sport=sport,
        dport=dport,
        seq=seq,
        ack=ack,
        flags=off_flags & 0x1FF,
        window=window,
        header_len=doff,
        payload_len=declared_len - doff,
    )
    opt_len = doff - 20
    if opt_len:
        if opt_len > r.remaining:
            # Options cut by snaplen; the fixed header is still good.
            r.skip(r.remaining)
        else:
            _tcp_options(r.sub(opt_len), tcp)
    return tcp


def decode_udp(r: ByteReader, declared_len: int) -> UDP:
    sport, dport, length, _csum = r.unpack(_UDP)
    if length < 8:
        if length == 0 and declared_len >= 8:
            length = declared_len  # UDP over IPv6 jumbograms, or offload
        else:
            raise DecodeError(f"UDP length {length} is below the minimum of 8")
    return UDP(sport=sport, dport=dport, payload_len=min(length, declared_len) - 8)


def _inner_ports(r: ByteReader, icmp: ICMP) -> None:
    if icmp.inner_proto in (PROTO_TCP, PROTO_UDP) and r.remaining >= 4:
        icmp.inner_sport, icmp.inner_dport = r.u16(), r.u16()


def decode_icmp(r: ByteReader) -> ICMP:
    icmp_type, code, _csum = r.unpack(_ICMP)
    icmp = ICMP(version=4, type=icmp_type, code=code)
    if icmp_type in (0, 8):
        icmp.echo_id, icmp.echo_seq = r.u16(), r.u16()
    elif icmp_type in (3, 5, 11, 12):
        rest = r.u32()
        if icmp_type == 3 and code == 4:
            icmp.mtu = rest & 0xFFFF
        # The quoted packet is often cut short; whatever we cannot read stays None.
        try:
            inner, inner_payload = decode_ipv4(r)
            icmp.inner_src, icmp.inner_dst, icmp.inner_proto = inner.src, inner.dst, inner.proto
            _inner_ports(inner_payload, icmp)
        except DecodeError:
            pass
    return icmp


def decode_icmpv6(r: ByteReader) -> ICMP:
    icmp_type, code, _csum = r.unpack(_ICMP)
    icmp = ICMP(version=6, type=icmp_type, code=code)
    if icmp_type in (128, 129):
        icmp.echo_id, icmp.echo_seq = r.u16(), r.u16()
    elif icmp_type in (1, 2, 3, 4):
        rest = r.u32()
        if icmp_type == 2:
            icmp.mtu = rest
        try:
            inner, inner_payload = decode_ipv6(r)
            icmp.inner_src, icmp.inner_dst, icmp.inner_proto = inner.src, inner.dst, inner.proto
            _inner_ports(inner_payload, icmp)
        except DecodeError:
            pass
    elif icmp_type in (135, 136):  # neighbour solicitation / advertisement
        r.skip(4)
        icmp.nd_target = _ntop6(r.take(16))
    return icmp


def decode_arp(r: ByteReader) -> ARP | None:
    htype, ptype, hlen, plen, op = r.unpack(_ARP)
    if htype != 1 or ptype != ETH_IPV4 or hlen != 6 or plen != 4:
        return None  # not Ethernet/IPv4 ARP; nothing we analyse
    sha = mac_str(r.take(6))
    spa = _inet_ntoa(r.take(4))
    tha = mac_str(r.take(6))
    tpa = _inet_ntoa(r.take(4))
    return ARP(op=op, sha=sha, spa=spa, tha=tha, tpa=tpa)


TRANSPORT_NAMES = {PROTO_ICMP: "ICMP", PROTO_TCP: "TCP", PROTO_UDP: "UDP", PROTO_ICMPV6: "ICMPv6"}
