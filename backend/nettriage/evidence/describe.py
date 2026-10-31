"""One-line, Wireshark-style summaries of packets, for evidence tables."""

from __future__ import annotations

from ..decode.dhcp import MSG_NAMES
from ..decode.dns import QTYPE_NAMES, RCODE_NAMES
from ..decode.layers import TRANSPORT_NAMES
from ..decode.model import ACK, CWR, ECE, FIN, PSH, RST, SYN, UNSPECIFIED, URG, Packet
from ..schema import KeyPacket

_FLAG_NAMES = [(SYN, "SYN"), (FIN, "FIN"), (RST, "RST"), (PSH, "PSH"), (ACK, "ACK"), (URG, "URG"),
               (ECE, "ECE"), (CWR, "CWR")]
_ICMP_UNREACH = {0: "Network unreachable", 1: "Host unreachable", 3: "Port unreachable",
                 4: "Fragmentation needed", 13: "Administratively prohibited"}


def tcp_flags(flags: int) -> str:
    names = [n for bit, n in _FLAG_NAMES if flags & bit]
    return ", ".join(names) if names else "none"


def _dns(p: Packet) -> str:
    d = p.dns
    q = d.questions[0] if d.questions else None
    qdesc = f"{QTYPE_NAMES.get(q.qtype, q.qtype)} {q.name}" if q else ""
    label = "mDNS" if d.multicast else "DNS"
    if not d.qr:
        return f"{label} query 0x{d.id:04x} {qdesc}"
    if d.rcode:
        return f"{label} response 0x{d.id:04x} {qdesc}: {RCODE_NAMES.get(d.rcode, d.rcode)}"
    answers = ", ".join(a.data for a in d.answers[:3])
    more = f" (+{len(d.answers) - 3})" if len(d.answers) > 3 else ""
    return f"{label} response 0x{d.id:04x} {qdesc} -> {answers or 'no answers'}{more}"


def _dhcp(p: Packet) -> str:
    d = p.dhcp
    name = MSG_NAMES.get(d.msg_type, "BOOTP")
    parts = [f"DHCP {name} xid 0x{d.xid:08x}"]
    if d.yiaddr != UNSPECIFIED:
        parts.append(f"offers {d.yiaddr}")
    if d.routers:
        parts.append(f"gateway {d.routers[0]}")
    if d.dns_servers:
        parts.append(f"DNS {', '.join(d.dns_servers[:2])}")
    if d.server_id:
        parts.append(f"server {d.server_id}")
    if d.hostname:
        parts.append(f"host '{d.hostname}'")
    return ", ".join(parts)


def summarize(p: Packet) -> tuple[str, str, str, str]:
    """(src, dst, protocol, summary) for one packet."""
    if p.arp:
        a = p.arp
        if a.op == 1:
            if a.spa == UNSPECIFIED:
                text = f"ARP probe: is anyone using {a.tpa}? (from {a.sha})"
            elif a.spa == a.tpa:
                text = f"Gratuitous ARP: {a.spa} is at {a.sha}"
            else:
                text = f"Who has {a.tpa}? Tell {a.spa}"
        else:
            text = f"{a.spa} is at {a.sha}" + (f" (to {a.tha})" if a.tha else "")
        return a.sha, (p.link.dst if p.link else a.tha) or "", "ARP", text
    src = p.ip.src if p.ip else (p.link.src if p.link else "")
    dst = p.ip.dst if p.ip else (p.link.dst if p.link else "")
    if p.dhcp:
        return src, dst, "DHCP", _dhcp(p)
    if p.dns:
        return src, dst, "mDNS" if p.dns.multicast else "DNS", _dns(p)
    if p.tcp:
        t = p.tcp
        return src, dst, "TCP", (f"{t.sport} -> {t.dport} [{tcp_flags(t.flags)}] seq={t.seq} ack={t.ack} "
                                 f"win={t.window} len={t.payload_len}")
    if p.udp:
        return src, dst, "UDP", f"{p.udp.sport} -> {p.udp.dport} len={p.udp.payload_len}"
    if p.icmp:
        i = p.icmp
        proto = "ICMP" if i.version == 4 else "ICMPv6"
        if i.version == 4 and i.type == 3:
            text = _ICMP_UNREACH.get(i.code, f"Destination unreachable (code {i.code})")
            if i.mtu is not None:
                text += f", next-hop MTU {i.mtu}"
        elif i.version == 6 and i.type == 2:
            text = f"Packet too big, MTU {i.mtu}"
        elif i.type in (8, 128):
            text = f"Echo request id={i.echo_id} seq={i.echo_seq}"
        elif i.type in (0, 129):
            text = f"Echo reply id={i.echo_id} seq={i.echo_seq}"
        else:
            text = f"type {i.type} code {i.code}"
        if i.inner_dst:
            text += f" (about {i.inner_src} -> {i.inner_dst})"
        return src, dst, proto, text
    if p.ip:
        return src, dst, TRANSPORT_NAMES.get(p.ip.proto, f"IP proto {p.ip.proto}"), f"IP protocol {p.ip.proto}"
    return src, dst, "Ethernet", f"ethertype 0x{p.link.ethertype:04x}" if p.link else "undecoded"


def key_packet(p: Packet, note: str = "") -> KeyPacket:
    src, dst, proto, text = summarize(p)
    if note:
        text = f"{text}  <- {note}"
    return KeyPacket(frame=p.frame, ts=p.ts, src=src, dst=dst, protocol=proto, summary=text)
