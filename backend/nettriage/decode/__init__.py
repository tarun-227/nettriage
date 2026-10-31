"""Packet decoding: RawPacket bytes in, model.Packet out, never an exception."""

from __future__ import annotations

from ..ingest.bytereader import ByteReader, DecodeError
from ..ingest.capture import RawPacket
from .dhcp import decode_dhcp
from .dns import decode_dns
from .layers import (
    SUPPORTED_LINKTYPES,
    decode_arp,
    decode_icmp,
    decode_icmpv6,
    decode_ipv4,
    decode_ipv6,
    decode_link,
    decode_tcp,
    decode_udp,
)
from .model import ETH_ARP, ETH_IPV4, ETH_IPV6, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, Packet

DNS_PORTS = {53}
MULTICAST_DNS_PORTS = {5353, 5355}
DHCP_PORTS = {67, 68}


def decode(raw: RawPacket) -> Packet:
    """Decode as many layers as the bytes allow.

    If a layer is malformed, the layers above it stay None and ``error`` names
    the layer. A packet cut short by the capture's snapshot length is not an
    error: we keep what was captured.
    """
    p = Packet(frame=raw.frame, ts=raw.ts_ns / 1e9, wire_len=raw.wire_len, cap_len=len(raw.data))
    if raw.linktype not in SUPPORTED_LINKTYPES:
        p.error = f"unsupported link type {raw.linktype}"
        return p
    r = ByteReader(raw.data)
    layer = "link-layer header"
    snap_cut = raw.wire_len > len(raw.data)
    try:
        p.link = link = decode_link(raw.linktype, r)
        if link.ethertype == ETH_ARP:
            layer = "ARP"
            p.arp = decode_arp(r)
            return p
        if link.ethertype == ETH_IPV4:
            layer = "IPv4 header"
            p.ip, payload = decode_ipv4(r)
        elif link.ethertype == ETH_IPV6:
            layer = "IPv6 header"
            p.ip, payload = decode_ipv6(r)
        else:
            return p
        ip = p.ip
        if ip.frag_offset:
            return p  # later fragments carry no transport header
        declared = ip.payload_len
        complete = payload.remaining >= declared and not ip.mf
        if ip.proto == PROTO_TCP:
            layer = "TCP header"
            p.tcp = decode_tcp(payload, declared)
            return p
        if ip.proto == PROTO_UDP:
            layer = "UDP header"
            p.udp = udp = decode_udp(payload, declared)
            ports = (udp.sport, udp.dport)
            if not complete and snap_cut:
                return p  # application data cut by snaplen; don't guess
            if udp.sport in DNS_PORTS or udp.dport in DNS_PORTS:
                layer = "DNS message"
                p.dns = decode_dns(payload.sub(min(udp.payload_len, payload.remaining)))
            elif udp.sport in MULTICAST_DNS_PORTS or udp.dport in MULTICAST_DNS_PORTS:
                layer = "mDNS/LLMNR message"
                p.dns = decode_dns(payload.sub(min(udp.payload_len, payload.remaining)), multicast=True)
            elif ports in ((67, 68), (68, 67)):
                layer = "DHCP message"
                p.dhcp = decode_dhcp(payload.sub(min(udp.payload_len, payload.remaining)))
            return p
        if ip.proto == PROTO_ICMP:
            layer = "ICMP message"
            p.icmp = decode_icmp(payload)
        elif ip.proto == PROTO_ICMPV6:
            layer = "ICMPv6 message"
            p.icmp = decode_icmpv6(payload)
    except DecodeError as e:
        if snap_cut and layer not in ("link-layer header",):
            # The capture stopped recording this packet early; not the network's fault.
            return p
        p.error = f"malformed {layer}"
        p.error_detail = str(e)
    return p
