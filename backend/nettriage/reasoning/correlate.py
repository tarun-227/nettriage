"""Link findings that share a root cause into incidents.

Two kinds of link:

- attacks by the same device: findings whose offending entity (the ARP claimant,
  the DNS forger, the scanner, the rogue DHCP server) is the same MAC or IP;
- an internet outage and the DNS failures it causes, which overlap in time.

Each incident names a root finding, the one to deal with first.
"""

from __future__ import annotations

import hashlib

from ..schema import Entity, Finding, Incident, Verdict

OFFENDER_ROLES = {"claimant", "forger", "scanner", "DHCP server"}
ROOT_PRIORITY = {"arp_spoofing": 0, "rogue_dhcp": 1, "dns_spoofing": 2, "dns_poisoning_attempt": 3, "port_scan": 4,
                 "network_sweep": 5}
OVERLAP_SLACK = 30.0

KIND_PHRASES = {
    "arp_spoofing": "impersonating the router",
    "rogue_dhcp": "running a rogue DHCP server",
    "dns_spoofing": "forging DNS answers",
    "dns_poisoning_attempt": "trying to poison DNS caches",
    "port_scan": "scanning for open ports",
    "network_sweep": "sweeping the network for devices",
}


def _id(findings: list[Finding]) -> str:
    key = "|".join(sorted(f.id for f in findings))
    return "incident-" + hashlib.sha1(key.encode(), usedforsecurity=False).hexdigest()[:10]


def _offenders(f: Finding) -> set[str]:
    return {e.value for e in f.entities if e.role in OFFENDER_ROLES}


def _same_device(attacks: list[Finding]) -> list[Incident]:
    # Union-find over findings that share an offending MAC or IP.
    parent = list(range(len(attacks)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: dict[str, int] = {}
    for i, f in enumerate(attacks):
        for value in _offenders(f):
            if value in owner:
                parent[find(i)] = find(owner[value])
            else:
                owner[value] = i
    groups: dict[int, list[Finding]] = {}
    for i, f in enumerate(attacks):
        groups.setdefault(find(i), []).append(f)

    incidents = []
    for members in groups.values():
        if len(members) < 2:
            continue
        members.sort(key=lambda f: (ROOT_PRIORITY.get(f.kind, 9), f.time_start))
        root = members[0]
        shared = set.intersection(*(_offenders(f) for f in members)) or _offenders(root)
        device = [e for e in root.entities if e.value in shared and e.role in OFFENDER_ROLES]
        who = next((e.value for e in device if e.kind == "mac"), None) or (device[0].value if device else "one device")
        kinds = {f.kind for f in members}
        if kinds == {"arp_spoofing", "dns_spoofing"}:
            title = f"Man-in-the-middle: {who} intercepts traffic and forges DNS answers"
        elif kinds == {"rogue_dhcp", "dns_spoofing"}:
            title = f"Rogue DHCP server {who} is also forging DNS answers"
        else:
            actions = [KIND_PHRASES.get(f.kind, f.kind.replace("_", " ")) for f in members]
            title = f"One device ({who}) is {', '.join(actions[:-1])} and {actions[-1]}"
        summary = (f"These {len(members)} findings point to the same device, {who}. "
                   + " ".join(f"It is {KIND_PHRASES.get(f.kind, 'involved in: ' + f.title)}."
                              for f in members)
                   + f" Start with \"{root.title}\": disconnecting {who} stops all of it.")
        incidents.append(Incident(
            id=_id(members), title=title, summary=summary, verdict=Verdict.ATTACK, root_finding=root.id,
            finding_ids=[f.id for f in members],
            entities=[Entity(kind=e.kind, value=e.value, role="attacker device") for e in device],
        ))
    return incidents


def _overlaps(a: Finding, b: Finding) -> bool:
    return a.time_start <= b.time_end + OVERLAP_SLACK and b.time_start <= a.time_end + OVERLAP_SLACK


def _outages(findings: list[Finding]) -> list[Incident]:
    incidents = []
    for outage in (f for f in findings if f.kind == "connectivity_outage" and f.verdict == Verdict.FAULT):
        dns = [f for f in findings if f.kind == "dns_failure" and f.verdict == Verdict.FAULT and _overlaps(outage, f)]
        if not dns:
            continue
        servers = [e.value for f in dns for e in f.entities if e.role == "DNS server"]
        resolver = servers[0] if servers else "the DNS server"
        members = [outage, *dns]
        incidents.append(Incident(
            id=_id(members),
            title="Internet outage: the DNS failures are a symptom",
            summary=(f"The internet connection stopped answering, and the DNS server ({resolver}) fails for the "
                     "same reason: it can't reach the servers it asks. Fix the connection first; DNS will recover "
                     "on its own."),
            verdict=Verdict.FAULT, root_finding=outage.id, finding_ids=[f.id for f in members],
            entities=[Entity(kind="ip", value=resolver, role="DNS server")] if servers else [],
        ))
    return incidents


def correlate(findings: list[Finding]) -> list[Incident]:
    """Incidents for the alert findings (attacks and faults), most serious first."""
    attacks = [f for f in findings if f.verdict == Verdict.ATTACK]
    return _same_device(attacks) + _outages(findings)
