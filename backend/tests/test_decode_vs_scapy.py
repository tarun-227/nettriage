"""Differential tests: our decoders must agree with Scapy on well-formed packets.

Scapy is a dev-only dependency. It builds the packets; it never parses for us.
"""

from __future__ import annotations

import pytest

scapy = pytest.importorskip("scapy.all")
from helpers import TS0, build_pcap, build_pcapng, read_all  # noqa: E402
from scapy.all import (  # noqa: E402
    ARP,
    BOOTP,
    DHCP,
    DNS,
    DNSQR,
    DNSRR,
    ICMP,
    IP,
    TCP,
    UDP,
    Dot1Q,
    Ether,
    ICMPv6PacketTooBig,
    IPv6,
    IPv6ExtHdrHopByHop,
)

MAC_A = "02:00:00:00:00:0a"
MAC_B = "02:00:00:00:00:0b"


def E():
    return Ether(src=MAC_A, dst=MAC_B)


def one(pkt) -> object:
    packets, counters = read_all(build_pcap([bytes(pkt)]))
    assert len(packets) == 1
    p = packets[0]
    assert p.error is None, p.error_detail
    return p


def test_tcp_syn_with_options():
    pkt = Ether(src=MAC_A, dst=MAC_B) / IP(src="10.0.0.5", dst="93.184.216.34", ttl=64, id=4321, flags="DF") / TCP(
        sport=40000, dport=443, flags="S", seq=1000,
        options=[("MSS", 1460), ("NOP", None), ("WScale", 7), ("SAckOK", b"")])
    p = one(pkt)
    assert (p.link.src, p.link.dst) == (MAC_A, MAC_B)
    assert (p.ip.src, p.ip.dst, p.ip.ttl, p.ip.ident, p.ip.df) == ("10.0.0.5", "93.184.216.34", 64, 4321, True)
    assert (p.tcp.sport, p.tcp.dport, p.tcp.seq, p.tcp.flags) == (40000, 443, 1000, 0x02)
    assert (p.tcp.mss, p.tcp.wscale, p.tcp.sack_ok) == (1460, 7, True)
    assert p.tcp.payload_len == 0


def test_tcp_payload_length_ignores_ethernet_padding():
    pkt = E() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(flags="A")
    raw = bytes(pkt) + b"\0" * 6  # pad to the 60-byte Ethernet minimum
    packets, _ = read_all(build_pcap([raw]))
    assert packets[0].tcp.payload_len == 0


def test_vlan_dns_query():
    pkt = E() / Dot1Q(vlan=10) / IP(src="10.0.0.5", dst="10.0.0.1") / UDP(sport=33333, dport=53) / DNS(
        id=0x1234, rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    p = one(pkt)
    assert p.link.vlan == 10
    assert p.dns.id == 0x1234 and not p.dns.qr and p.dns.rd
    assert p.dns.qname == "example.com"
    assert p.dns.questions[0].qtype == 1


def test_dns_response_with_answers():
    pkt = E() / IP(src="10.0.0.1", dst="10.0.0.5") / UDP(sport=53, dport=33333) / DNS(
        id=7, qr=1, ra=1, rcode=0, qd=DNSQR(qname="www.example.com"),
        an=[DNSRR(rrname="www.example.com", type="CNAME", rdata="example.com", ttl=300),
            DNSRR(rrname="example.com", type="A", rdata="93.184.216.34", ttl=60)])
    p = one(pkt)
    assert p.dns.qr and p.dns.rcode == 0
    assert [(a.name, a.rtype, a.ttl, a.data) for a in p.dns.answers] == [
        ("www.example.com", 5, 300, "example.com"),
        ("example.com", 1, 60, "93.184.216.34"),
    ]


def test_arp_request():
    pkt = Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=MAC_A, psrc="10.0.0.5", pdst="10.0.0.1")
    p = one(pkt)
    assert (p.arp.op, p.arp.sha, p.arp.spa, p.arp.tpa) == (1, MAC_A, "10.0.0.5", "10.0.0.1")


def test_dhcp_offer():
    pkt = Ether(src=MAC_B) / IP(src="10.0.0.1", dst="255.255.255.255") / UDP(sport=67, dport=68) / BOOTP(
        op=2, yiaddr="10.0.0.50", chaddr=bytes.fromhex("02000000000a"), xid=0xDEADBEEF) / DHCP(options=[
            ("message-type", "offer"), ("server_id", "10.0.0.1"), ("router", "10.0.0.1"),
            ("name_server", "8.8.8.8", "1.1.1.1"), ("lease_time", 3600), ("subnet_mask", "255.255.255.0"),
            ("hostname", b"gw"), "end"])
    p = one(pkt)
    d = p.dhcp
    assert (d.op, d.xid, d.chaddr, d.yiaddr, d.msg_type) == (2, 0xDEADBEEF, MAC_A, "10.0.0.50", 2)
    assert (d.server_id, d.routers, d.dns_servers) == ("10.0.0.1", ["10.0.0.1"], ["8.8.8.8", "1.1.1.1"])
    assert (d.lease_time, d.subnet_mask, d.hostname) == (3600, "255.255.255.0", "gw")


def test_icmp_fragmentation_needed_quotes_inner_flow():
    pkt = E() / IP(src="10.0.0.1", dst="10.0.0.5") / ICMP(type=3, code=4, nexthopmtu=1400) / IP(
        src="10.0.0.5", dst="1.2.3.4") / TCP(sport=40000, dport=443)
    p = one(pkt)
    i = p.icmp
    assert (i.type, i.code, i.mtu) == (3, 4, 1400)
    assert (i.inner_src, i.inner_dst, i.inner_proto, i.inner_sport, i.inner_dport) == (
        "10.0.0.5", "1.2.3.4", 6, 40000, 443)


def test_ipv6_with_extension_header():
    pkt = E() / IPv6(src="fe80::1", dst="fe80::2") / IPv6ExtHdrHopByHop() / TCP(sport=1, dport=2, flags="SA")
    p = one(pkt)
    assert (p.ip.version, p.ip.src, p.ip.dst, p.ip.proto) == (6, "fe80::1", "fe80::2", 6)
    assert (p.tcp.sport, p.tcp.dport, p.tcp.flags) == (1, 2, 0x12)


def test_icmpv6_packet_too_big():
    pkt = E() / IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6PacketTooBig(mtu=1280) / IPv6(
        src="2001:db8::2", dst="2001:db8::9") / UDP(sport=5000, dport=6000)
    p = one(pkt)
    assert (p.icmp.version, p.icmp.type, p.icmp.mtu) == (6, 2, 1280)
    assert (p.icmp.inner_dst, p.icmp.inner_sport, p.icmp.inner_dport) == ("2001:db8::9", 5000, 6000)


def test_snaplen_cut_dns_is_not_an_error():
    pkt = E() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=53, dport=4000) / DNS(qr=1, qd=DNSQR(qname="a-long-name.example.org"))
    data = bytes(pkt)
    from helpers import pcap_header, pcap_record
    capture = pcap_header() + pcap_record(data[:50], TS0, wire_len=len(data))
    packets, counters = read_all(capture)
    assert packets[0].error is None
    assert packets[0].udp is not None and packets[0].dns is None
    assert counters.skipped == 0


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("nanos", [False, True])
def test_pcap_variants_and_timestamps(endian, nanos):
    frames = [bytes(E() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP()) for _ in range(3)]
    packets, counters = read_all(build_pcap(frames, endian=endian, nanos=nanos, step=0.25))
    assert [p.frame for p in packets] == [1, 2, 3]
    assert [round(p.ts - TS0, 6) for p in packets] == [0.0, 0.25, 0.5]
    assert counters.format == "pcap"


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("tsresol", [None, 9])
def test_pcapng_variants(endian, tsresol):
    frames = [bytes(E() / IP(src="10.0.0.1") / UDP()) for _ in range(3)]
    packets, counters = read_all(build_pcapng(frames, endian=endian, tsresol=tsresol))
    assert [p.frame for p in packets] == [1, 2, 3]
    assert [round(p.ts - TS0) for p in packets] == [0, 1, 2]
    assert all(p.ip.src == "10.0.0.1" for p in packets)
    assert counters.format == "pcapng"
