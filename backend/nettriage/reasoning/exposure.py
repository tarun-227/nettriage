"""Blast radius: what an interceptor could actually see.

The ARP detector proves interception by catching the same packet arriving at the attacker's MAC and
leaving it again with the TTL lowered by one. Every packet caught that way belongs to a conversation
that passed through the attacker. Here those conversations are grouped by victim, server and service,
named with the DNS answers the victim received, and classed by what crossing the attacker exposed:

- encrypted services (HTTPS, SSH, IMAPS...): which server and when, not the contents;
- plaintext services that carry logins (HTTP, FTP, Telnet, POP3, IMAP, SMTP...): everything;
- DNS: every name looked up, and the answers could be forged.

Nothing is extracted from the payloads: the report says what was readable, never what it said.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict

from ..schema import ExposedFlow, Exposure, Finding, Verdict

MAX_FLOWS = 40

# port -> (service, encrypted). None means the protocol may or may not be encrypted.
SERVICES: dict[int, tuple[str, bool | None]] = {
    443: ("HTTPS", True), 8443: ("HTTPS", True), 853: ("DNS over TLS", True), 993: ("IMAPS", True),
    995: ("POP3S", True), 465: ("SMTPS", True), 22: ("SSH", True), 3389: ("RDP", True), 5061: ("SIP over TLS", True),
    80: ("HTTP", False), 8080: ("HTTP", False), 21: ("FTP", False), 23: ("Telnet", False), 25: ("SMTP", False),
    110: ("POP3", False), 143: ("IMAP", False), 53: ("DNS", False), 389: ("LDAP", False), 161: ("SNMP", False),
    5060: ("SIP", False), 69: ("TFTP", False), 445: ("SMB", None), 587: ("SMTP submission", None),
}
PROTO = {6: "TCP", 17: "UDP", 1: "ICMP"}

READABLE = "Everything, including any password typed"
METADATA = "Which server and when, not the contents"
NAMES = "Every name looked up; answers could be forged"
MAYBE = "Possibly everything: may or may not be encrypted"
UNKNOWN = "Possibly everything: protocol not recognised"


def _service(sport: int, dport: int) -> tuple[int | None, bool]:
    """The service port of a conversation, and whether the packet's destination is the server."""
    for port, to_server in ((dport, True), (sport, False)):
        if port in SERVICES:
            return port, to_server
    if dport and dport < 1024 <= sport:
        return dport, True
    if sport and sport < 1024 <= dport:
        return sport, False
    return (dport or None), True


def _private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _exposed(service: str, encrypted: bool | None) -> str:
    if service == "DNS":
        return NAMES
    if encrypted:
        return METADATA
    if encrypted is None:
        return MAYBE if service in {s for s, _ in SERVICES.values()} else UNKNOWN
    return READABLE


def _span(seconds: float) -> str:
    seconds = max(0.0, seconds)
    return f"{seconds:.0f} s" if seconds < 90 else f"{seconds / 60:.0f} min"


def blast_radius(alerts: list[Finding], relay_flows: dict[str, dict[tuple, list]],
                 dns_names: dict[str, str]) -> list[Exposure]:
    out = []
    for f in alerts:
        if f.kind != "arp_spoofing" or f.verdict != Verdict.ATTACK:
            continue
        attacker = next((e.value for e in f.entities if e.kind == "mac" and e.role == "claimant"), None)
        flows = relay_flows.get(attacker or "", {})
        if not attacker or not flows:
            continue
        # Fold both directions of a conversation together: (victim, server, proto, service port).
        convo: dict[tuple, list] = defaultdict(lambda: [0, float("inf"), 0.0, []])
        for (src, dst, proto, sport, dport), (count, t0, t1, frames) in flows.items():
            port, to_server = _service(sport, dport)
            client, server = (src, dst) if to_server else (dst, src)
            if proto not in (6, 17):
                port = None
            c = convo[(client, server, proto, port)]
            c[0] += count
            c[1] = min(c[1], t0)
            c[2] = max(c[2], t1)
            c[3].extend(frames[: 6 - len(c[3])])

        items = []
        for (client, server, proto, port), (count, t0, t1, frames) in convo.items():
            fallback = f"{PROTO.get(proto, 'IP')} {port}" if port else PROTO.get(proto, "IP")
            service, encrypted = SERVICES.get(port, (fallback, None))
            items.append(ExposedFlow(
                victim=client, peer=server, name=dns_names.get(server), protocol=PROTO.get(proto, str(proto)),
                port=port, service=service, encrypted=encrypted, exposed=_exposed(service, encrypted),
                packets=count, first_ts=t0, last_ts=t1, frames=sorted(frames)))
        risk = {READABLE: 0, NAMES: 1, MAYBE: 2, UNKNOWN: 2, METADATA: 3}
        items.sort(key=lambda x: (risk[x.exposed], -x.packets))

        victims = sorted({x.victim for x in items if _private(x.victim)}) or sorted({x.victim for x in items})
        hijacked = sorted({e.value for g in alerts if g.kind == "dns_spoofing" and g.verdict == Verdict.ATTACK
                           and any(e2.kind == "mac" and e2.value == attacker for e2 in g.entities)
                           for e in g.entities if e.kind == "domain"})
        readable = [x for x in items if x.exposed == READABLE]
        metadata = [x for x in items if x.exposed == METADATA]
        dns = [x for x in items if x.exposed == NAMES]
        start = min(x.first_ts for x in items)
        end = max(x.last_ts for x in items)
        label = lambda x: x.name or x.peer  # noqa: E731

        could = []
        if readable:
            could.append(f"read {len(readable)} unencrypted connection(s) in full "
                         f"({', '.join(sorted({x.service for x in readable}))})")
        if metadata:
            could.append(f"see which servers {len(metadata)} encrypted connection(s) went to, but not their contents")
        if dns:
            could.append("see every name looked up")
        if hijacked:
            could.append(f"send {', '.join(hijacked)} to a fake address")
        who = ", ".join(victims[:3]) + (f" and {len(victims) - 3} more" if len(victims) > 3 else "")
        summary = (f"{attacker} sat in the middle of {who}'s traffic for {_span(end - start)}. "
                   f"It could {'; '.join(could) if could else 'see the relayed packets'}.")

        steps = []
        for x in readable[:4]:
            steps.append(f"Change any password used over {x.service} with {label(x)} by {x.victim}: "
                         "it crossed the network unencrypted while being intercepted.")
        if hijacked:
            steps.append(f"Clear the DNS cache on {who} (ipconfig /flushdns on Windows) so "
                         f"{', '.join(hijacked)} resolve to the real servers again, and don't trust what those "
                         "sites showed during the attack.")
        if metadata:
            steps.append("Encrypted connections kept their contents private. If anyone clicked through a certificate "
                         "warning during the attack, treat that site as exposed too.")

        attacker_ips = sorted({e.value for e in f.entities if e.kind == "ip" and e.role == "attacker address"})
        out.append(Exposure(
            finding_id=f.id, attacker=attacker, attacker_ips=attacker_ips, victims=victims, start=start, end=end,
            relayed_packets=sum(x.packets for x in items), flows=items[:MAX_FLOWS], hijacked_names=hijacked,
            readable=len(readable), metadata_only=len(metadata), summary=summary, fix_steps=steps))
    return out
