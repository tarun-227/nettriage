"""MITRE ATT&CK techniques for attack findings, so a report lines up with how security teams file incidents."""

from __future__ import annotations

from ..schema import Finding, Technique, Verdict

_BASE = "https://attack.mitre.org/techniques/"

TECHNIQUES: dict[str, list[tuple[str, str]]] = {
    "arp_spoofing": [("T1557.002", "Adversary-in-the-Middle: ARP Cache Poisoning")],
    "rogue_dhcp": [("T1557.003", "Adversary-in-the-Middle: DHCP Spoofing")],
    "dns_spoofing": [("T1557", "Adversary-in-the-Middle")],
    "dns_poisoning_attempt": [("T1557", "Adversary-in-the-Middle")],
    "port_scan": [("T1046", "Network Service Discovery")],
    "network_sweep": [("T1018", "Remote System Discovery")],
}


def tag_techniques(findings: list[Finding]) -> None:
    for f in findings:
        if f.verdict != Verdict.ATTACK:
            continue
        f.techniques = [Technique(id=tid, name=name, url=_BASE + tid.replace(".", "/") + "/")
                        for tid, name in TECHNIQUES.get(f.kind, [])]
