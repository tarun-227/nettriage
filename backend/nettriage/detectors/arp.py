"""ARP integrity: who really owns each IP address on the local network.

Two kinds of finding come out of this detector:

1. An IP address claimed by more than one MAC. That is scored against four
   explanations: ARP spoofing (attack), duplicate IP (fault), router failover
   or a replaced device (benign). Spoofing is the only one that needs to lie
   in targeted, unrequested replies and to relay the victim's traffic, and
   those are the strongest signals. See docs/research.md.
2. An IP address nobody answers for: a device that is off (fault), or one
   host sweeping the subnet (attack).
"""

from __future__ import annotations

import statistics
from collections import Counter, OrderedDict, defaultdict
from dataclasses import dataclass, field

from ..config import Limits
from ..decode.dhcp import ACK as DHCP_ACK
from ..decode.model import PROTO_TCP, PROTO_UDP, PROTO_VRRP, UNSPECIFIED, Packet
from ..evidence.describe import key_packet
from ..reasoning.differential import Differential, HypothesisDef, Observation, Rule
from ..reasoning.finding import Narrative, build_finding
from ..schema import Entity, Finding, KeyPacket, Verdict
from .base import Context, Detector, is_multicast_mac

BROADCAST = "ff:ff:ff:ff:ff:ff"
VIRTUAL_MAC_PREFIXES = ("00:00:5e:00:01:", "00:00:5e:00:02:", "00:00:0c:07:ac:", "00:00:0c:9f:f", "00:07:b4:00:")
REDUNDANCY_UDP_PORTS = {1985, 2029, 3222}  # HSRPv1, HSRPv2, GLBP
SOLICIT_WINDOW = 3.0
RELAY_WINDOW = 0.05
MAX_CLAIMS_PER_IP = 5000
MAX_KEY_PACKETS = 40
SWEEP_TARGETS = 20

# --- binding conflicts ---------------------------------------------------

CONFLICT = Differential(
    [
        HypothesisDef("spoof", "ARP spoofing (man-in-the-middle)", Verdict.ATTACK, prior=-2.0),
        HypothesisDef("dup", "Duplicate IP address", Verdict.FAULT, prior=-1.0),
        HypothesisDef("failover", "Router failover", Verdict.BENIGN, prior=-0.5),
        HypothesisDef("replaced", "Device or network card replaced", Verdict.BENIGN, prior=-0.5),
    ],
    [
        Rule("targeted_unsolicited", "spoof", 3.0,
             "{count} ARP replies nobody asked for, sent straight to {victim_count} host(s)"),
        Rule("targeted_unsolicited", "dup", -1.0, "A misconfigured device answers questions; it does not push "
             "unrequested replies at specific hosts"),
        Rule("targeted_unsolicited", "failover", -1.0, "Failover announces once, to everyone, not to chosen hosts"),
        Rule("targeted_unsolicited", "replaced", -1.5, "A replaced device has no reason to push unrequested replies"),
        Rule("periodic_poisoning", "spoof", 1.5,
             "The unrequested replies repeat every {period:.1f} s like clockwork, the pattern of "
             "spoofing tools that keep victims' caches poisoned"),
        Rule("gratuitous_announcement", "failover", 1.0, "{count} broadcast announcement(s) of the address change"),
        Rule("gratuitous_announcement", "replaced", 0.8, "The new device announced itself with a broadcast"),
        Rule("gratuitous_announcement", "dup", 0.5, "The second device announced the address it was configured with"),
        Rule("flip_flop", "spoof", 1.0, "The address kept switching between the two MACs ({changes} changes)"),
        Rule("flip_flop", "dup", 1.5, "The address keeps switching between two MACs ({changes} changes), as when "
             "two devices fight over it"),
        Rule("flip_flop", "failover", -2.0, "Failover moves an address once; this one keeps switching back"),
        Rule("flip_flop", "replaced", -2.5, "A replaced device's old MAC would not keep coming back"),
        Rule("single_switch", "replaced", 1.5, "The address moved once and stayed"),
        Rule("single_switch", "failover", 1.5, "The address moved once and stayed"),
        Rule("single_switch", "spoof", -1.0, "Spoofing usually has to fight the real owner, but this moved once"),
        Rule("single_switch", "dup", -1.0, "Two devices sharing an address usually keep fighting over it"),
        Rule("incumbent_silent_after", "replaced", 1.5, "The old MAC went silent after the change"),
        Rule("incumbent_silent_after", "failover", 1.0, "The old MAC went silent after the change"),
        Rule("incumbent_silent_after", "spoof", -1.5, "The original owner disappeared, so nobody was impersonated"),
        Rule("incumbent_silent_after", "dup", -1.5, "Only one device was left using the address"),
        Rule("both_active", "spoof", 0.5,
             "The original owner was still active while the other MAC claimed its address"),
        Rule("both_active", "dup", 1.0, "Both devices were active at the same time"),
        Rule("both_active", "replaced", -2.0, "The old device is still active, so it was not replaced"),
        Rule("both_active", "failover", -0.5, "The old router kept sending traffic after the change"),
        Rule("dad_conflict", "dup", 3.0, "A device checked whether {ip} was free (an RFC 5227 probe) and {owner} "
             "answered that it was taken"),
        Rule("dad_conflict", "spoof", -0.5, "The newcomer asked before using the address, which attackers don't"),
        Rule("both_answer_requests", "dup", 2.5, "{count} time(s) both MACs answered the same question about {ip}"),
        Rule("both_answer_requests", "spoof", 0.3, "Both MACs answered the same question"),
        Rule("challenger_originates_ip", "dup", 2.0, "{other} sends its own traffic from {ip} ({count} packets), "
             "so it really is configured with that address"),
        Rule("challenger_originates_ip", "spoof", -1.0, "{other} uses {ip} for its own traffic, not just in ARP"),
        Rule("challenger_originates_ip", "replaced", 0.5, "The new device uses the address normally"),
        Rule("challenger_has_own_ip", "spoof", 1.0, "{other} also has its own address ({own_ips}), so {ip} is not "
             "its real identity"),
        Rule("challenger_has_own_ip", "replaced", -1.0, "A replacement device would have only this one address"),
        Rule("challenger_has_own_ip", "dup", -0.5, "{other} also uses another address"),
        Rule("claims_gateway", "spoof", 0.8, "{ip} is the gateway, the most valuable address to impersonate"),
        Rule("claims_gateway", "failover", 0.5, "{ip} is the gateway, which is what failover protects"),
        Rule("multi_ip_claims", "spoof", 2.0, "{other} claims {count} addresses that belong to other devices "
             "({ips}), positioning itself between them"),
        Rule("multi_ip_claims", "dup", -1.0, "A misconfigured device takes one wrong address, not several"),
        Rule("relay_proof", "spoof", 4.0, "{count} packet(s) were addressed to {other} and then re-sent by it to "
             "their real destination with the TTL lowered by one: it is relaying the traffic it intercepts"),
        Rule("relay_proof", "dup", -2.0, "A duplicate-address device does not forward other hosts' traffic"),
        Rule("relay_proof", "replaced", -2.0, "A normal device does not forward other hosts' traffic"),
        Rule("relay_proof", "failover", -1.5, "Relaying through a second hop is not how failover works"),
        Rule("redundancy_protocol", "failover", 4.0, "{device} sends {protocol} advertisements, a router "
             "redundancy protocol"),
        Rule("redundancy_protocol", "spoof", -1.5, "A redundancy protocol is running, which explains the change"),
        Rule("redundancy_protocol", "dup", -1.0, "A redundancy protocol is running, which explains the change"),
        Rule("virtual_mac", "failover", 3.0, "{other} is a VRRP/HSRP virtual router MAC"),
        Rule("dhcp_lease_to_challenger", "replaced", 3.0, "The DHCP server leased {ip} to {other} (frame {frame})"),
        Rule("dhcp_lease_to_challenger", "spoof", -2.0, "The address was handed to {other} by DHCP"),
        Rule("dhcp_lease_to_challenger", "dup", -1.5, "DHCP assigned the address, which normally prevents conflicts"),
        Rule("eth_arp_mismatch", "spoof", 1.5, "{count} ARP packet(s) claim a sender MAC different from the "
             "Ethernet source, which only hand-crafted packets do"),
    ],
)

CONFLICT_TEXT = {
    "spoof": Narrative(
        kind="arp_spoofing",
        title="{other} is impersonating {target}",
        simple=("A device on your network ({other}{other_ip_note}) is pretending to be {target}. Computers that "
                "believe it send their traffic to it first, so it can read or change what they send{relay_note}."),
        technical=("{other} sent {unsolicited} unrequested ARP replies binding {ips} to its MAC "
                   "(real owner: {owner}){period_note}.{relay_tech}"),
        cause=("ARP has no authentication, so any device can claim any address. Tools such as arpspoof, ettercap "
               "and bettercap use this to intercept traffic (a man-in-the-middle attack)."),
        fix=("Find the device with MAC {other}{other_ip_hint} in your switch's MAC address table or the router's "
             "client list, and disconnect it.",
             "Turn on Dynamic ARP Inspection or ARP protection on your switch or router if it has it.",
             "Until it is removed, don't sign in to anything from {victims}.",
             "Change passwords that were typed on {victims} after {start_time}."),
    ),
    "dup": Narrative(
        kind="duplicate_ip",
        title="Two devices are using {ip}",
        simple=("Two devices ({owner} and {other}) are set to the same IP address, {ip}. Traffic for that "
                "address goes to one or the other at random, so connections to it fail or drop."),
        technical="{ip} is claimed by {owner} and {other}: {dup_detail}.",
        cause=("Usually a device with a manually set (static) address inside the DHCP range, or two devices "
               "given the same static address."),
        fix=("Find the newer device ({other}) and switch it to automatic (DHCP) addressing, or give it an "
             "address outside the DHCP range.",
             "Use DHCP reservations in the router instead of typing addresses into devices.",
             "Reconnect {owner} to the network afterwards so it picks the address back up."),
    ),
    "failover": Narrative(
        kind="arp_benign_change",
        title="{ip} moved to a backup router",
        simple=("The gateway address {ip} moved from {owner} to {other}, and {other} runs a router redundancy "
                "protocol. This is a planned failover, not an attack."),
        technical="Single change of the {ip} binding from {owner} to {other} at {switch_time}; {redundancy_note}.",
        cause="The main router stopped answering and the backup took over its address, as designed.",
        fix=("Nothing to fix on the network. Check why the main router ({owner}) failed over, e.g. a reboot "
             "or power cut.",),
    ),
    "replaced": Narrative(
        kind="arp_benign_change",
        title="{ip} moved to a different device",
        simple=("The address {ip} moved from {owner} to {other} once and stayed there{lease_note}. That is what "
                "replacing a device or its network card looks like; nothing suggests an attack."),
        technical="Single binding change {owner} -> {other} at {switch_time}; the old MAC went quiet{lease_tech}.",
        cause="A device or network adapter was replaced, or the address was leased to another device.",
        fix=("Nothing to fix. If you don't recognise {other}, check the router's list of connected devices.",),
    ),
}

# --- unanswered addresses -------------------------------------------------

SILENT = Differential(
    [
        HypothesisDef("down", "Device switched off or disconnected", Verdict.FAULT, prior=-0.5),
        HypothesisDef("quiet", "Occasional harmless lookup", Verdict.BENIGN, prior=0.5),
        HypothesisDef("capture", "Replies missing from the capture", Verdict.BENIGN, prior=-1.0),
    ],
    [
        Rule("many_requests", "down", 1.5, "{count} requests for {ip} went unanswered"),
        Rule("many_requests", "quiet", -1.0, "Far more lookups than a stray shortcut would cause"),
        Rule("multiple_requesters", "down", 2.0, "{count} different devices tried to reach {ip}"),
        Rule("multiple_requesters", "quiet", -1.0, "Several devices need this address"),
        Rule("retries", "down", 1.0, "Devices retried in quick succession, as they do when a host they need is gone"),
        Rule("previously_alive", "down", 1.0, "{ip} answered earlier in the capture, then stopped"),
        Rule("traffic_to_target", "capture", 4.0, "Devices still send traffic to {ip}, so it must have answered "
             "outside what was captured"),
        Rule("traffic_to_target", "down", -3.0, "Devices still send traffic to {ip}, so it is not unknown to them"),
    ],
)

SILENT_TEXT = {
    "down": Narrative(
        kind="host_unreachable",
        title="{ip} is not responding on the local network",
        simple=("Devices on your network tried {count} times to reach {ip}, and nothing answered. The device at "
                "that address is probably off, unplugged, or now has a different address."),
        technical=("{count} ARP requests for {ip} from {requesters} host(s) between {first} and {last}; no ARP "
                   "reply and no traffic from {ip}.{prev_note}"),
        cause="The device is off, disconnected, asleep, or its address changed.",
        fix=("Check that the device at {ip} is powered on and its cable or Wi-Fi is connected.",
             "If it now has a new address, update whatever still points at {ip} (a printer or file share "
             "shortcut), or reserve the address for it in DHCP.",
             "If it must stay reachable, turn off power saving for its network adapter."),
    ),
    "quiet": Narrative(
        kind="arp_unanswered",
        title="A few unanswered lookups for {ip}",
        simple="A handful of lookups for {ip} got no answer. That is common and harmless (an old shortcut or a "
               "device that left).",
        technical="{count} ARP request(s) for {ip}, no reply.",
        cause="A stale reference to a device that is no longer on the network.",
        fix=("Nothing to fix.",),
    ),
    "capture": Narrative(
        kind="arp_unanswered",
        title="Replies for {ip} are missing from the capture",
        simple="Requests for {ip} look unanswered, but devices are still talking to it, so the replies were simply "
               "not captured.",
        technical="Unanswered ARP for {ip} while unicast traffic to {ip} continues.",
        cause="The capture point does not see both directions.",
        fix=("Capture on a mirror port that copies both directions.",),
    ),
}

SWEEP_TEXT = Narrative(
    kind="network_sweep",
    title="{requester} is sweeping the network for devices",
    simple=("{requester} asked for {count} different addresses in {span}, and most of them don't exist. That is how "
            "an attacker (or an inventory tool) maps a network before probing it."),
    technical="{count} distinct ARP targets from {requester} ({mac}); {unanswered} unanswered.",
    cause="Network discovery: an ARP scan by a tool such as nmap -sn, arp-scan or netdiscover.",
    fix=("Find {requester} ({mac}). If it isn't an IT tool you run, disconnect it and check it for malware.",),
)


def fmt_time(ts: float) -> str:
    import datetime as dt
    return dt.datetime.fromtimestamp(ts, dt.UTC).strftime("%H:%M:%S UTC")


@dataclass
class Claim:
    mac: str
    ts: float
    frame: int
    kind: str  # reply, unsolicited, gratuitous, request


@dataclass
class MacState:
    first_ts: float
    last_ts: float
    ips: set[str] = field(default_factory=set)
    unsolicited: list[tuple[float, int, str, str]] = field(default_factory=list)  # ts, frame, claimed ip, victim
    gratuitous: list[tuple[float, int, str]] = field(default_factory=list)
    eth_mismatch: list[int] = field(default_factory=list)


class ArpDetector(Detector):
    name = "arp"

    def __init__(self, limits: Limits):
        super().__init__(limits)
        self.macs: dict[str, MacState] = {}
        self.claims: dict[str, list[Claim]] = defaultdict(list)
        self.pending: dict[tuple[str, str], float] = {}
        self.responders: dict[tuple[str, str, float], list[tuple[str, int]]] = defaultdict(list)
        self.probes: dict[str, tuple[float, str, int]] = {}
        self.dad: dict[str, list[tuple[int, str, str]]] = defaultdict(list)
        self.requests: dict[str, list[tuple[float, str, int]]] = defaultdict(list)
        self.last_reply: dict[str, float] = {}
        self.ip_dst_seen: Counter = Counter()
        self.originated: dict[str, Counter] = defaultdict(Counter)
        self.recent: OrderedDict = OrderedDict()
        self.relays: dict[str, list[tuple[int, int]]] = defaultdict(list)
        self.redundancy: dict[str, str] = {}
        self.leases: dict[str, list[tuple[str, int]]] = defaultdict(list)
        self.kp: dict[str, list[KeyPacket]] = defaultdict(list)
        self.capped = False

    # --- per packet -----------------------------------------------------

    def _mac(self, mac: str, ts: float) -> MacState | None:
        st = self.macs.get(mac)
        if st is None:
            if len(self.macs) >= self.limits.max_hosts:
                self.capped = True
                return None
            st = self.macs[mac] = MacState(ts, ts)
        st.last_ts = ts
        return st

    def _key(self, bucket, p: Packet, note: str = "", cap: int = 12) -> None:
        lst = self.kp[bucket]
        if len(lst) < cap:
            lst.append(key_packet(p, note))

    def on_packet(self, p: Packet) -> None:
        link = p.link
        if link and link.src and not is_multicast_mac(link.src):
            self._mac(link.src, p.ts)
        if p.arp:
            self._arp(p)
            return
        ip = p.ip
        if ip is None or link is None or not link.src:
            return
        if ip.proto == PROTO_VRRP:
            self.redundancy.setdefault(link.src, "VRRP/CARP")
        elif p.udp and p.udp.dport in REDUNDANCY_UDP_PORTS:
            self.redundancy.setdefault(link.src, "HSRP" if p.udp.dport != 3222 else "GLBP")
        if p.dhcp and p.dhcp.msg_type == DHCP_ACK and p.dhcp.chaddr and p.dhcp.yiaddr != UNSPECIFIED:
            self.leases[p.dhcp.yiaddr].append((p.dhcp.chaddr, p.frame))
        if link.dst and not is_multicast_mac(link.dst):
            self.ip_dst_seen[ip.dst] += 1
        if ip.version == 4 and link.dst:
            self._relay(p)

    def _relay(self, p: Packet) -> None:
        ip, link = p.ip, p.link
        if p.tcp:
            extra = (p.tcp.sport, p.tcp.dport, p.tcp.seq, p.tcp.payload_len)
        elif p.udp:
            extra = (p.udp.sport, p.udp.dport, p.udp.payload_len, 0)
        else:
            extra = (0, 0, ip.payload_len, 0)
        key = (ip.src, ip.dst, ip.ident, ip.proto, *extra)
        prev = self.recent.get(key)
        relayed = (prev is not None and prev[1] == link.src and prev[0] != link.src
                   and 0 <= p.ts - prev[3] <= RELAY_WINDOW and ip.ttl == prev[2] - 1)
        if relayed:
            self.relays[link.src].append((prev[4], p.frame))
            self._key(("relay", link.src), p, f"relayed by {link.src}, TTL {prev[2]} -> {ip.ttl}", cap=6)
        elif ip.proto in (PROTO_TCP, PROTO_UDP) or ip.proto == 1:
            self.originated[ip.src][link.src] += 1
        self.recent[key] = (link.src, link.dst, ip.ttl, p.ts, p.frame)
        if len(self.recent) > 50_000:
            self.recent.popitem(last=False)

    def _claim(self, ip: str, mac: str, p: Packet, kind: str) -> None:
        if ip in (UNSPECIFIED, "255.255.255.255") or ip.startswith("169.254."):
            return
        lst = self.claims[ip]
        if len(lst) < MAX_CLAIMS_PER_IP:
            lst.append(Claim(mac, p.ts, p.frame, kind))
        st = self.macs.get(mac)
        if st is not None:
            st.ips.add(ip)
        if kind != "request":
            self._key((ip, mac), p, {"unsolicited": "unrequested reply", "gratuitous": "announcement"}.get(kind, ""))

    def _arp(self, p: Packet) -> None:
        a = p.arp
        st = self._mac(a.sha, p.ts)
        if st is None:
            return
        if p.link and p.link.src and p.link.src != a.sha and len(st.eth_mismatch) < 50:
            st.eth_mismatch.append(p.frame)
        if a.op == 1:
            if a.spa == UNSPECIFIED:
                self.probes[a.tpa] = (p.ts, a.sha, p.frame)
                self._key(a.tpa, p)
                return
            if a.spa == a.tpa:
                st.gratuitous.append((p.ts, p.frame, a.spa))
                self._claim(a.spa, a.sha, p, "gratuitous")
                return
            self._claim(a.spa, a.sha, p, "request")
            self.pending[(a.spa, a.tpa)] = p.ts
            reqs = self.requests[a.tpa]
            if len(reqs) < 2000:
                reqs.append((p.ts, a.spa, p.frame))
            self._key(("req", a.tpa), p, cap=8)
            return
        if a.op != 2:
            return
        self.last_reply[a.spa] = p.ts
        t_req = self.pending.get((a.tpa, a.spa))
        solicited = t_req is not None and 0 <= p.ts - t_req <= SOLICIT_WINDOW
        if solicited:
            self.responders[(a.tpa, a.spa, t_req)].append((a.sha, p.frame))
        probe = self.probes.get(a.spa)
        if probe and 0 <= p.ts - probe[0] <= 2.0 and probe[1] != a.sha:
            self.dad[a.spa].append((p.frame, a.sha, probe[1]))
            self._key((a.spa, a.sha), p, "defends the address against a probe")
            solicited = True
        broadcast = p.link is not None and p.link.dst == BROADCAST
        if solicited:
            kind = "reply"
        elif a.spa == a.tpa or broadcast:
            kind = "gratuitous"
            st.gratuitous.append((p.ts, p.frame, a.spa))
        else:
            kind = "unsolicited"
            if len(st.unsolicited) < 5000:
                st.unsolicited.append((p.ts, p.frame, a.spa, a.tpa))
        self._claim(a.spa, a.sha, p, kind)

    # --- end of capture -------------------------------------------------

    def finalize(self, ctx: Context) -> list[Finding]:
        if self.capped:
            ctx.counters.state_caps_hit.add("ARP host table")
        findings = self._conflicts(ctx)
        findings += self._silent(ctx)
        return findings

    def _incumbent(self, ip: str, macs: list[str]) -> str:
        # The first MAC that claimed the address in a normal way (answering, asking, announcing).
        # A MAC whose only claims are unrequested replies is never the owner, even if the
        # capture starts mid-attack.
        for c in self.claims[ip]:
            if c.kind != "unsolicited":
                return c.mac
        return macs[0]

    def _conflicts(self, ctx: Context) -> list[Finding]:
        gateway_macs = ctx.gateway_macs()
        disputes: dict[str, list[tuple[str, str]]] = defaultdict(list)  # challenger -> [(ip, owner)]
        for ip, claims in self.claims.items():
            macs = list(dict.fromkeys(c.mac for c in claims))
            if len(macs) < 2:
                continue
            owner = self._incumbent(ip, macs)
            for m in macs:
                if m != owner:
                    disputes[m].append((ip, owner))
        out = []
        for challenger, items in disputes.items():
            f = self._conflict_finding(challenger, items, gateway_macs, ctx)
            if f:
                out.append(f)
        return out

    def _conflict_finding(self, other: str, items: list[tuple[str, str]], gateway_macs: set[str],
                          ctx: Context) -> Finding | None:
        st = self.macs.get(other)
        if st is None:
            return None
        disputed = [ip for ip, _ in items]
        ip, owner = items[0]
        # Report the most valuable address first: the gateway if it is among them.
        for cand_ip, cand_owner in items:
            if cand_owner in gateway_macs:
                ip, owner = cand_ip, cand_owner
                break
        obs: list[Observation] = []
        frames: list[int] = []

        unsolicited = [u for u in st.unsolicited if u[2] in disputed]
        if unsolicited:
            victims = {u[3] for u in unsolicited}
            obs.append(Observation("targeted_unsolicited", [u[1] for u in unsolicited],
                                   {"count": len(unsolicited), "victim_count": len(victims)},
                                   strength=min(1.0, len(unsolicited) / 4)))
            frames += [u[1] for u in unsolicited]
            gaps = [b[0] - a[0] for a, b in zip(unsolicited, unsolicited[1:], strict=False) if b[0] - a[0] > 0.2]
            if len(gaps) >= 3:
                mean = statistics.fmean(gaps)
                cv = statistics.pstdev(gaps) / mean if mean else 1.0
                if cv < 0.35:
                    obs.append(Observation("periodic_poisoning", [], {"period": mean}))

        grat = [g for g in st.gratuitous if g[2] in disputed]
        if grat:
            obs.append(Observation("gratuitous_announcement", [g[1] for g in grat], {"count": len(grat)}))
            frames += [g[1] for g in grat]

        # Sequence of owners for the main address, keeping only the two MACs in question.
        seq = [c for c in self.claims[ip] if c.mac in (owner, other)]
        switches = 0
        for a, b in zip(seq, seq[1:], strict=False):
            if a.mac != b.mac:
                switches += 1
        first_other = next((c for c in seq if c.mac == other), None)
        owner_after = [c for c in seq if c.mac == owner and first_other and c.ts > first_other.ts]
        if switches >= 2 and owner_after:
            obs.append(Observation("flip_flop", [c.frame for c in seq[:40]], {"changes": switches}))
        elif switches == 1 and not owner_after:
            obs.append(Observation("single_switch"))
        owner_state = self.macs.get(owner)
        t_switch = first_other.ts if first_other else st.first_ts
        if owner_state and owner_state.last_ts > t_switch + 2.0:
            obs.append(Observation("both_active"))
        else:
            obs.append(Observation("incumbent_silent_after"))

        for d_ip in disputed:
            if self.dad.get(d_ip):
                dad = self.dad[d_ip]
                obs.append(Observation("dad_conflict", [d[0] for d in dad], {"ip": d_ip, "owner": dad[0][1]}))
                frames += [d[0] for d in dad]
                break
        both = [r for (asker, target, _), r in self.responders.items()
                if target in disputed and len({m for m, _ in r}) >= 2]
        if both:
            fr = [f for r in both for _, f in r]
            obs.append(Observation("both_answer_requests", fr, {"count": len(both), "ip": ip}))
            frames += fr
        originated = sum(self.originated[d][other] for d in disputed)
        if originated:
            obs.append(Observation("challenger_originates_ip", [], {"count": originated, "other": other, "ip": ip}))
        own_ips = sorted(st.ips - set(disputed))
        if own_ips:
            obs.append(Observation("challenger_has_own_ip", [], {"own_ips": ", ".join(own_ips[:3]),
                                                                 "other": other, "ip": ip}))
        is_gateway = owner in gateway_macs
        if is_gateway:
            obs.append(Observation("claims_gateway", [], {"ip": ip}))
        if len(disputed) >= 2:
            obs.append(Observation("multi_ip_claims", [], {"count": len(disputed), "ips": ", ".join(disputed[:4]),
                                                           "other": other}))
        relays = self.relays.get(other, [])
        if relays:
            fr = [f for pair in relays[:20] for f in pair]
            obs.append(Observation("relay_proof", fr, {"count": len(relays), "other": other},
                                   strength=min(1.0, len(relays) / 3)))
            frames += fr
        for m in (other, owner):
            if m in self.redundancy:
                obs.append(Observation("redundancy_protocol", [], {"device": m, "protocol": self.redundancy[m]}))
                break
        if other.startswith(VIRTUAL_MAC_PREFIXES):
            obs.append(Observation("virtual_mac", [], {"other": other}))
        lease = next(((m, f) for d in disputed for m, f in self.leases.get(d, []) if m == other), None)
        if lease:
            obs.append(Observation("dhcp_lease_to_challenger", [lease[1]], {"ip": ip, "other": other,
                                                                             "frame": lease[1]}))
            frames.append(lease[1])
        if st.eth_mismatch:
            obs.append(Observation("eth_arp_mismatch", st.eth_mismatch, {"count": len(st.eth_mismatch)}))

        other_claims = [c for d in disputed for c in self.claims[d] if c.mac == other]
        frames += [c.frame for c in other_claims[:100]]
        sufficient = len(other_claims) >= 2 or bool(relays) or lease is not None
        diagnosis = CONFLICT.diagnose(obs, sufficient=sufficient)

        times = [c.ts for c in other_claims] or [st.first_ts]
        victims = sorted({u[3] for u in unsolicited}) or [d for d in disputed if d != ip]
        target = f"the router ({ip})" if is_gateway else ip
        dup_bits = []
        if any(o.feature == "dad_conflict" for o in obs):
            dup_bits.append("an address-conflict probe was answered")
        if both:
            dup_bits.append(f"both answered {len(both)} request(s)")
        if originated:
            dup_bits.append(f"{other} sends traffic as {ip}")
        ctx_text = {
            "ip": ip, "ips": ", ".join(disputed), "owner": owner, "other": other, "target": target,
            "other_ip_note": f", which also uses {own_ips[0]}" if own_ips else "",
            "other_ip_hint": f" (it also uses {own_ips[0]})" if own_ips else "",
            "relay_note": (", and the capture shows it relaying their packets" if relays else ""),
            "relay_tech": (f" {len(relays)} packet(s) were relayed by {other} with the TTL lowered by one, "
                           "which confirms the interception." if relays else ""),
            "unsolicited": len(unsolicited),
            "period_note": next((f", repeating every {o.detail['period']:.1f} s" for o in obs
                                 if o.feature == "periodic_poisoning"), ""),
            "victims": ", ".join(victims[:4]) if victims else "the affected computers",
            "start_time": fmt_time(min(times)),
            "switch_time": fmt_time(t_switch),
            "dup_detail": "; ".join(dup_bits) or "both claim it in ARP",
            "redundancy_note": (f"{self.redundancy.get(other) or self.redundancy.get(owner)} advertisements seen"
                                if (other in self.redundancy or owner in self.redundancy)
                                else "the old MAC went quiet afterwards"),
            "lease_note": " after a DHCP lease" if lease else "",
            "lease_tech": f"; DHCP leased {ip} to {other} in frame {lease[1]}" if lease else "",
        }
        entities = [Entity(kind="ip", value=d, role="claimed address") for d in disputed]
        entities += [Entity(kind="mac", value=other, role="claimant"),
                     Entity(kind="mac", value=owner, role="original owner")]
        entities += [Entity(kind="ip", value=v, role="victim") for v in victims[:5] if v not in disputed]
        # Lead with the claimant's packets and the relayed traffic; a few of the owner's for contrast.
        kps = [k for d in disputed for k in self.kp.get((d, other), [])][:12]
        kps += self.kp.get(("relay", other), [])
        kps += [k for d in disputed for k in self.kp.get((d, owner), [])][:3]
        return build_finding(
            analyzer=self.name, diagnosis=diagnosis, narratives=CONFLICT_TEXT, ctx=ctx_text, entities=entities,
            frames=frames, key_packets=kps, time_start=min(times), time_end=max(times),
            wireshark_filter=f"arp.src.hw_mac == {other} || (arp.src.proto_ipv4 == {ip})",
            impact="critical_asset" if is_gateway else "single_host",
            max_frames=self.limits.max_evidence_frames,
        )

    def _silent(self, ctx: Context) -> list[Finding]:
        # Requests made after the address last answered (plus the usual reply window) went unanswered.
        unanswered = {}
        for ip, reqs in self.requests.items():
            if ip.startswith("169.254."):
                continue
            cutoff = self.last_reply.get(ip, float("-inf")) + SOLICIT_WINDOW
            late = [r for r in reqs if r[0] > cutoff and (ctx.last_ts is None or r[0] < ctx.last_ts - 1.0)]
            if len(late) >= 3:
                unanswered[ip] = late
        # One host asking for many addresses that don't exist is a sweep, not many dead hosts.
        by_requester: dict[str, set[str]] = defaultdict(set)
        for ip, reqs in self.requests.items():
            for _, asker, _ in reqs:
                by_requester[asker].add(ip)
        sweepers = {r for r, targets in by_requester.items() if len(targets) >= SWEEP_TARGETS
                    and sum(1 for t in targets if t not in self.last_reply) >= SWEEP_TARGETS * 0.6}
        out = [self._sweep_finding(r, by_requester[r]) for r in sweepers]
        for ip, reqs in unanswered.items():
            requesters = {a for _, a, _ in reqs}
            if requesters <= sweepers:
                continue
            obs = [Observation("many_requests", [f for _, _, f in reqs], {"count": len(reqs), "ip": ip},
                               strength=min(1.0, len(reqs) / 6))]
            if len(requesters) >= 2:
                obs.append(Observation("multiple_requesters", [], {"count": len(requesters), "ip": ip}))
            per_req = Counter(a for _, a, _ in reqs)
            if per_req and per_req.most_common(1)[0][1] >= 3:
                obs.append(Observation("retries"))
            if ip in self.last_reply:
                obs.append(Observation("previously_alive", [], {"ip": ip}))
            if self.ip_dst_seen.get(ip, 0) >= 5 or ip in ctx.silent_ips():
                obs.append(Observation("traffic_to_target", [], {"ip": ip}))
            diagnosis = SILENT.diagnose(obs, sufficient=len(reqs) >= 3)
            ctx_text = {"ip": ip, "count": len(reqs), "requesters": len(requesters),
                        "first": fmt_time(reqs[0][0]), "last": fmt_time(reqs[-1][0]),
                        "prev_note": " It did answer earlier in the capture." if ip in self.last_reply else ""}
            out.append(build_finding(
                analyzer=self.name, diagnosis=diagnosis, narratives=SILENT_TEXT, ctx=ctx_text,
                entities=[Entity(kind="ip", value=ip, role="unreachable host")]
                + [Entity(kind="ip", value=r, role="requester") for r in sorted(requesters)[:5]],
                frames=[f for _, _, f in reqs], key_packets=self.kp.get(("req", ip), []),
                time_start=reqs[0][0], time_end=reqs[-1][0],
                wireshark_filter=f"arp.dst.proto_ipv4 == {ip}",
                impact="single_host" if len(requesters) < 3 else "multi_host",
                max_frames=self.limits.max_evidence_frames,
            ))
        return out

    def _sweep_finding(self, requester: str, targets: set[str]) -> Finding:
        reqs = sorted((r for t in targets for r in self.requests[t] if r[1] == requester), key=lambda r: r[0])
        mac = next((m for m, s in self.macs.items() if requester in s.ips), "unknown MAC")
        unanswered = sum(1 for t in targets if t not in self.last_reply)
        diagnosis = Differential(
            [HypothesisDef("sweep", "Network discovery sweep", Verdict.ATTACK, prior=0.0),
             HypothesisDef("tool", "IT inventory tool", Verdict.BENIGN, prior=-1.0)],
            [Rule("targets", "sweep", 2.5, "{count} distinct addresses requested, {unanswered} unanswered")],
        ).diagnose([Observation("targets", [r[2] for r in reqs[:50]],
                                {"count": len(targets), "unanswered": unanswered})])
        span = reqs[-1][0] - reqs[0][0] if reqs else 0
        return build_finding(
            analyzer=self.name, diagnosis=diagnosis, narratives={"sweep": SWEEP_TEXT, "tool": SWEEP_TEXT},
            ctx={"requester": requester, "mac": mac, "count": len(targets), "unanswered": unanswered,
                 "span": f"{span:.0f} seconds"},
            entities=[Entity(kind="ip", value=requester, role="scanner"), Entity(kind="mac", value=mac,
                                                                                 role="scanner")],
            frames=[r[2] for r in reqs], key_packets=[], time_start=reqs[0][0] if reqs else 0,
            time_end=reqs[-1][0] if reqs else 0, wireshark_filter=f"arp.src.proto_ipv4 == {requester}",
            impact="multi_host", max_frames=self.limits.max_evidence_frames,
        )
