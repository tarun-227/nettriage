"""Decoded packet model. Detectors only ever see these objects, never raw bytes."""

from __future__ import annotations

from dataclasses import dataclass, field

# TCP flag bits
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58
PROTO_VRRP = 112

# The unspecified IPv4 address, used as the sender of ARP probes and DHCP discovers.
UNSPECIFIED = "0.0.0.0"  # noqa: S104 - an address we compare against, never one we bind to

ETH_IPV4 = 0x0800
ETH_ARP = 0x0806
ETH_IPV6 = 0x86DD


@dataclass(slots=True)
class Link:
    src: str | None
    dst: str | None
    ethertype: int
    vlan: int | None = None


@dataclass(slots=True)
class IP:
    version: int
    src: str
    dst: str
    proto: int
    ttl: int
    ident: int | None
    df: bool
    mf: bool
    frag_offset: int
    header_len: int
    payload_len: int         # as declared by the header, not as captured


@dataclass(slots=True)
class TCP:
    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    window: int
    header_len: int
    payload_len: int
    mss: int | None = None
    wscale: int | None = None
    sack_ok: bool = False


@dataclass(slots=True)
class UDP:
    sport: int
    dport: int
    payload_len: int


@dataclass(slots=True)
class ICMP:
    version: int             # 4 or 6
    type: int
    code: int
    mtu: int | None = None   # next-hop MTU (v4 frag-needed) or PTB MTU (v6)
    echo_id: int | None = None
    echo_seq: int | None = None
    # The offending packet quoted inside an error message.
    inner_src: str | None = None
    inner_dst: str | None = None
    inner_proto: int | None = None
    inner_sport: int | None = None
    inner_dport: int | None = None
    nd_target: str | None = None


@dataclass(slots=True)
class ARP:
    op: int                  # 1 request, 2 reply
    sha: str
    spa: str
    tha: str
    tpa: str


@dataclass(slots=True)
class DNSQuestion:
    name: str
    qtype: int
    qclass: int


@dataclass(slots=True)
class DNSRecord:
    name: str
    rtype: int
    ttl: int
    data: str


@dataclass(slots=True)
class DNS:
    id: int
    qr: bool
    opcode: int
    aa: bool
    tc: bool
    rd: bool
    ra: bool
    rcode: int
    questions: list[DNSQuestion] = field(default_factory=list)
    answers: list[DNSRecord] = field(default_factory=list)
    multicast: bool = False  # mDNS or LLMNR

    @property
    def qname(self) -> str | None:
        return self.questions[0].name if self.questions else None


@dataclass(slots=True)
class DHCP:
    op: int
    xid: int
    chaddr: str | None
    ciaddr: str
    yiaddr: str
    siaddr: str
    giaddr: str
    msg_type: int | None = None
    server_id: str | None = None
    requested_ip: str | None = None
    subnet_mask: str | None = None
    routers: list[str] = field(default_factory=list)
    dns_servers: list[str] = field(default_factory=list)
    lease_time: int | None = None
    hostname: str | None = None
    vendor_class: str | None = None


@dataclass(slots=True)
class Packet:
    frame: int
    ts: float
    wire_len: int
    cap_len: int
    link: Link | None = None
    ip: IP | None = None
    tcp: TCP | None = None
    udp: UDP | None = None
    icmp: ICMP | None = None
    arp: ARP | None = None
    dns: DNS | None = None
    dhcp: DHCP | None = None
    error: str | None = None          # category, e.g. "malformed IPv4 header"
    error_detail: str | None = None

    @property
    def src(self) -> str | None:
        if self.ip:
            return self.ip.src
        if self.arp:
            return self.arp.spa
        return self.link.src if self.link else None

    @property
    def dst(self) -> str | None:
        if self.ip:
            return self.ip.dst
        if self.arp:
            return self.arp.tpa
        return self.link.dst if self.link else None
