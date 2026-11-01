"""Detector interface and the shared context every detector can read at the end of the pass."""

from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import dataclass, field
from functools import lru_cache

from ..config import Limits
from ..decode.model import Packet
from ..ingest.capture import IngestCounters
from ..schema import Finding, QualityWarning

# "Local" in the sense a small office means it: addresses that never leave the site.
# (Python's is_private also covers the documentation ranges, which we treat as internet.)
_LOCAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8", "100.64.0.0/10",
    "fc00::/7", "fe80::/10", "::1/128")]


@lru_cache(maxsize=65536)
def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _LOCAL_NETS if n.version == a.version)


@lru_cache(maxsize=65536)
def is_public_unicast(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (is_private(ip) or a.is_multicast or a.is_unspecified or a.is_reserved
                or ip == "255.255.255.255")


def is_multicast_mac(mac: str | None) -> bool:
    return bool(mac) and int(mac[:2], 16) & 1 == 1


@dataclass
class Context:
    """Facts gathered during the pass that more than one detector needs."""

    limits: Limits
    counters: IngestCounters
    first_ts: float | None = None
    last_ts: float | None = None
    # MACs that deliver traffic from or to public addresses: the gateway(s).
    offsubnet_macs: Counter = field(default_factory=Counter)
    # Frames sent and received per MAC, used to spot one-directional captures.
    tx_by_mac: Counter = field(default_factory=Counter)
    rx_by_mac: Counter = field(default_factory=Counter)
    # Unicast IP destination -> the MAC that frames for it were sent to.
    rx_ip_mac: dict[str, Counter] = field(default_factory=dict)
    quality: list[QualityWarning] = field(default_factory=list)
    # Addresses returned in DNS answers: things people actually tried to reach.
    dns_answers: set[str] = field(default_factory=set)
    # Address -> the name a client looked up to get it (first answer wins), to name relayed connections.
    dns_names: dict[str, str] = field(default_factory=dict)
    # Sources the port-scan detector flagged; other detectors leave their traffic out.
    scanners: set[str] = field(default_factory=set)
    # (host, host) pairs whose retransmissions the MTU detector explains; TCP health leaves them out.
    mtu_pairs: set[tuple[str, str]] = field(default_factory=set)

    def gateway_silent(self) -> bool:
        """True if the busiest destination MAC (normally the gateway) never transmits in the capture."""
        top = self.rx_by_mac.most_common(1)
        return bool(top) and top[0][0] in self.silent_macs()

    def silent_macs(self) -> set[str]:
        """MACs that receive plenty of unicast traffic but never send anything we can see."""
        return {m for m, n in self.rx_by_mac.items() if n >= 20 and self.tx_by_mac.get(m, 0) == 0}

    def silent_ips(self) -> set[str]:
        silent = self.silent_macs()
        return {ip for ip, macs in self.rx_ip_mac.items() if macs and macs.most_common(1)[0][0] in silent}

    @property
    def duration(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return max(0.0, self.last_ts - self.first_ts)

    def gateway_macs(self) -> set[str]:
        if not self.offsubnet_macs:
            return set()
        top = self.offsubnet_macs.most_common(1)[0][1]
        return {m for m, n in self.offsubnet_macs.items() if n >= max(5, top * 0.5)}

    def warn(self, code: str, message: str, detail: str = "") -> None:
        if not any(w.code == code for w in self.quality):
            self.quality.append(QualityWarning(code=code, message=message, detail=detail))


class Detector:
    name = "base"

    def __init__(self, limits: Limits):
        self.limits = limits

    def on_packet(self, p: Packet) -> None:
        raise NotImplementedError

    def finalize(self, ctx: Context) -> list[Finding]:
        raise NotImplementedError
