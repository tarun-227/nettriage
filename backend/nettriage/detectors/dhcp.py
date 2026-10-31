"""DHCP: rogue servers, misconfigured servers, and devices nobody gives an address to.

Instead of needing a list of authorised servers, we infer the legitimate one
from the capture: the server whose offered gateway actually carries the
office's internet traffic, then the one that was seen first. Every other server
is weighed against three explanations (docs/research.md):

- rogue (attack): same subnet, but gateway or DNS points back at itself, so
  clients keep working while their traffic is intercepted;
- misconfigured (fault): a different subnet, typically a home router plugged in
  backwards, so clients that take its offer lose connectivity;
- redundant (benign): a failover partner offering the same gateway and DNS.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import dataclass, field

from ..config import Limits
from ..decode.dhcp import ACK, DISCOVER, NAK, OFFER, REQUEST
from ..decode.model import UNSPECIFIED, Packet
from ..evidence.describe import key_packet
from ..reasoning.differential import Differential, HypothesisDef, Observation, Rule
from ..reasoning.finding import Narrative, build_finding
from ..schema import Entity, Finding, Verdict
from .arp import fmt_time
from .base import Context, Detector

# A few OUI prefixes, enough to recognise the usual suspects. Kept small and offline on purpose.
CONSUMER_ROUTER_OUIS = {
    "c0:4a:00": "TP-Link", "50:c7:bf": "TP-Link", "14:cc:20": "TP-Link", "a0:40:a0": "Netgear",
    "c4:04:15": "Netgear", "04:d4:c4": "ASUS", "2c:fd:a1": "ASUS", "1c:7e:e5": "D-Link", "c8:d7:19": "Linksys",
    "e4:8d:8c": "MikroTik", "b0:be:76": "TP-Link", "f4:f2:6d": "TP-Link",
}
VM_OUIS = {"08:00:27": "VirtualBox", "00:0c:29": "VMware", "00:50:56": "VMware", "52:54:00": "QEMU/KVM",
           "00:15:5d": "Hyper-V"}


@dataclass
class Server:
    ident: str
    mac: str | None
    offers: int = 0
    acks: int = 0
    naks: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    routers: Counter = field(default_factory=Counter)
    dns: Counter = field(default_factory=Counter)
    subnets: Counter = field(default_factory=Counter)
    pool: set = field(default_factory=set)
    frames: list = field(default_factory=list)
    clients: set = field(default_factory=set)
    accepted: set = field(default_factory=set)
    relayed: bool = False
    kp: list = field(default_factory=list)


@dataclass
class Exchange:
    chaddr: str | None
    first_ts: float
    discovers: int = 0
    frames: list = field(default_factory=list)
    offers: list = field(default_factory=list)  # (server ident, ts)
    kp: list = field(default_factory=list)


SERVERS = Differential(
    [
        HypothesisDef("rogue", "Rogue DHCP server", Verdict.ATTACK, prior=-1.5),
        HypothesisDef("misconfig", "Misconfigured second DHCP server", Verdict.FAULT, prior=-0.5),
        HypothesisDef("redundant", "Redundant DHCP server", Verdict.BENIGN, prior=0.0),
    ],
    [
        Rule("same_subnet", "rogue", 1.5, "It hands out addresses in the office subnet ({subnet}), so clients keep "
             "working and notice nothing"),
        Rule("same_subnet", "misconfig", -2.0, "Its addresses fit the office network"),
        Rule("same_subnet", "redundant", 1.0, "Its addresses fit the office network"),
        Rule("other_subnet", "misconfig", 3.0, "It hands out {subnet}, a different network from the office's "
             "{legit_subnet}, so clients that take it lose their connection"),
        Rule("other_subnet", "rogue", -1.5, "Interceptors keep victims working, and this breaks them"),
        Rule("other_subnet", "redundant", -3.0, "A partner server would use the same network"),
        Rule("self_gateway", "rogue", 1.5, "It names itself ({ip}) as the gateway, instead of {legit_router}"),
        Rule("self_gateway", "misconfig", 0.8, "It names itself as the gateway, as home routers do"),
        Rule("self_gateway", "redundant", -2.0, "A partner server would hand out the real gateway"),
        Rule("self_dns", "rogue", 1.0, "It names itself as the DNS server, so it can answer every lookup"),
        Rule("self_dns", "misconfig", 0.5, "It names itself as the DNS server"),
        Rule("same_options", "redundant", 4.0, "It hands out the same gateway ({router}) and DNS ({dns}) as "
             "{legit}"),
        Rule("same_options", "rogue", -3.0, "Its settings send clients to the real gateway and DNS"),
        Rule("same_options", "misconfig", -2.0, "Its settings match the legitimate server"),
        Rule("faster", "rogue", 0.7, "Its offers arrived before the legitimate server's in {count} exchange(s)"),
        Rule("accepted", "rogue", 0.5, "{count} device(s) took its offer"),
        Rule("accepted", "misconfig", 0.5, "{count} device(s) took its offer"),
        Rule("consumer_router", "misconfig", 1.0, "Its MAC belongs to {vendor}, a home/small-office router maker"),
        Rule("vm_host", "rogue", 1.0, "Its MAC belongs to {vendor}, a virtual machine, a common attacker setup"),
        Rule("relay", "redundant", 1.0, "Its offers came through a DHCP relay, as central servers' do"),
    ],
)

SERVER_TEXT = {
    "rogue": Narrative(
        kind="rogue_dhcp",
        title="Rogue DHCP server at {ip}",
        simple=("A device ({ip}, {mac}) is handing out network settings that make new devices use it as their "
                "gateway{dns_part}. The addresses fit your network so nothing looks broken, but {accepted} "
                "device(s) now send their traffic through it, where it can be watched or changed."),
        technical=("OFFER/ACK from server {ip} ({mac}): gateway {router}, DNS {dns}, addresses {pool}. Legitimate "
                   "server {legit} offers gateway {legit_router}.{race}"),
        cause="Someone is running an unauthorised DHCP server to intercept traffic (e.g. with Yersinia, ettercap "
              "or a rogue access point).",
        fix=("Find and disconnect the device with MAC {mac}.",
             "Turn on DHCP snooping on your switch so only the router's port may answer DHCP.",
             "On {victims}, disconnect and reconnect to get a lease from {legit}, then check their DNS settings."),
    ),
    "misconfig": Narrative(
        kind="dhcp_misconfigured_server",
        title="A second DHCP server is handing out the wrong network ({ip})",
        simple=("A device at {ip} ({mac}{vendor_note}) gives out addresses in {subnet}, a different network from "
                "yours ({legit_subnet}). Devices that take one lose their connection. This usually means a home "
                "router was plugged in by one of its LAN ports."),
        technical="OFFER/ACK from {ip} ({mac}): addresses {pool}, gateway {router}, DNS {dns}; legitimate server "
                  "{legit} uses {legit_subnet}. {accepted} client(s) accepted.",
        cause="A home or spare router with its DHCP server switched on, connected to the office network.",
        fix=("Unplug the device at {ip} ({mac}), or turn off its DHCP server.",
             "If it must stay, connect the office network to its WAN/Internet port, not a LAN port.",
             "Reconnect the affected devices ({victims}) so they get a correct address."),
    ),
    "redundant": Narrative(
        kind="dhcp_redundant_servers",
        title="Two DHCP servers share the job",
        simple="{ip} and {legit} both answer DHCP and give out the same gateway and DNS. That is a normal "
               "redundant setup.",
        technical="{ip} offers gateway {router}, DNS {dns}; same as {legit}.",
        cause="Planned DHCP failover or a relay setup.",
        fix=("Nothing to fix. Make sure their address pools don't overlap.",),
    ),
}

NO_OFFER = Differential(
    [
        HypothesisDef("down", "No DHCP server answering", Verdict.FAULT, prior=0.0),
        HypothesisDef("capture", "Replies missing from the capture", Verdict.BENIGN, prior=-1.0),
    ],
    [
        Rule("repeated", "down", 2.0, "{count} requests for an address (DISCOVER) went unanswered"),
        Rule("clients", "down", 1.0, "{count} different devices were affected"),
        Rule("no_server", "down", 1.0, "No DHCP server answered anyone during the capture"),
        Rule("silent_capture", "capture", 4.0, "The capture shows no traffic at all from the network's routers"),
        Rule("silent_capture", "down", -2.5, "Replies may simply be missing from the capture"),
    ],
)

NO_OFFER_TEXT = {
    "down": Narrative(
        kind="dhcp_no_offer",
        title="Devices can't get a network address",
        simple=("{clients} device(s) asked for a network address {count} times and no DHCP server answered. "
                "Without an address they can't get online at all."),
        technical="{count} DISCOVERs from {clients} client(s) ({macs}) with no OFFER between {first} and {last}.",
        cause="The DHCP server (usually the router) is off, crashed or has its DHCP service disabled, its address "
              "pool is full, or the devices are on a network segment it can't hear.",
        fix=("Restart the router and check that its DHCP server is enabled.",
             "Check whether the DHCP address pool is full (too many devices or very long leases).",
             "If only some devices are affected, check their switch port or VLAN."),
    ),
    "capture": Narrative(
        kind="capture_one_directional", title="DHCP replies are missing from the capture",
        simple="Requests for addresses look unanswered, but the capture contains no traffic from the routers at "
               "all, so it is probably one-directional.",
        technical="{count} unanswered DISCOVERs.", cause="Capture setup.", fix=("Capture both directions.",)),
}


def _subnet(ip: str, mask: str | None) -> str:
    try:
        return str(ipaddress.ip_network(f"{ip}/{mask or '255.255.255.0'}", strict=False))
    except ValueError:
        return f"{ip}/?"


class DhcpDetector(Detector):
    name = "dhcp"

    def __init__(self, limits: Limits):
        super().__init__(limits)
        self.servers: dict[str, Server] = {}
        self.exchanges: dict[tuple[str | None, int], Exchange] = {}
        self.ip_mac: dict[str, str] = {}

    def on_packet(self, p: Packet) -> None:
        if p.arp and p.arp.op == 2 and len(self.ip_mac) < self.limits.max_hosts:
            self.ip_mac.setdefault(p.arp.spa, p.arp.sha)
            return
        d = p.dhcp
        if d is None or d.msg_type is None:
            return
        key = (d.chaddr, d.xid)
        ex = self.exchanges.get(key)
        if ex is None:
            if len(self.exchanges) >= self.limits.max_hosts:
                return
            ex = self.exchanges[key] = Exchange(d.chaddr, p.ts)
        if d.msg_type == DISCOVER:
            ex.discovers += 1
            if len(ex.frames) < 20:
                ex.frames.append(p.frame)
            if len(ex.kp) < 3:
                ex.kp.append(key_packet(p))
            return
        if d.msg_type == REQUEST:
            if d.server_id and d.server_id in self.servers and d.chaddr:
                self.servers[d.server_id].accepted.add(d.chaddr)
            return
        if d.msg_type not in (OFFER, ACK, NAK):
            return
        ident = d.server_id or (p.ip.src if p.ip else "unknown")
        srv = self.servers.get(ident)
        if srv is None:
            if len(self.servers) >= 64:
                return
            srv = self.servers[ident] = Server(ident, p.link.src if p.link else None, first_ts=p.ts)
        srv.last_ts = p.ts
        if d.giaddr != UNSPECIFIED:
            srv.relayed = True
        if len(srv.frames) < 100:
            srv.frames.append(p.frame)
        if len(srv.kp) < 4:
            srv.kp.append(key_packet(p))
        if d.msg_type == NAK:
            srv.naks += 1
            return
        if d.msg_type == OFFER:
            srv.offers += 1
            ex.offers.append((ident, p.ts))
        else:
            srv.acks += 1
            if d.chaddr:
                srv.accepted.add(d.chaddr)
        if d.chaddr:
            srv.clients.add(d.chaddr)
        if d.yiaddr != UNSPECIFIED:
            srv.pool.add(d.yiaddr)
            srv.subnets[_subnet(d.yiaddr, d.subnet_mask)] += 1
        if d.routers:
            srv.routers[d.routers[0]] += 1
        for s in d.dns_servers[:2]:
            srv.dns[s] += 1

    def finalize(self, ctx: Context) -> list[Finding]:
        out = self._no_offer(ctx)
        if len(self.servers) < 2:
            return out
        gateways = ctx.gateway_macs()

        def legitimacy(s: Server) -> tuple:
            router = s.routers.most_common(1)[0][0] if s.routers else None
            carries = (router is not None and self.ip_mac.get(router) in gateways) or s.mac in gateways
            return (carries, -s.first_ts, s.acks)

        legit = max(self.servers.values(), key=legitimacy)
        for s in self.servers.values():
            if s is not legit and (s.offers or s.acks):
                out.append(self._server_finding(s, legit))
        return out

    def _server_finding(self, s: Server, legit: Server) -> Finding:
        subnet = s.subnets.most_common(1)[0][0] if s.subnets else "unknown"
        legit_subnet = legit.subnets.most_common(1)[0][0] if legit.subnets else "unknown"
        router = s.routers.most_common(1)[0][0] if s.routers else "none"
        legit_router = legit.routers.most_common(1)[0][0] if legit.routers else "unknown"
        dns = ", ".join(d for d, _ in s.dns.most_common(2)) or "none"
        legit_dns = ", ".join(d for d, _ in legit.dns.most_common(2)) or "none"
        obs = []
        if legit.subnets and s.subnets:
            if subnet == legit_subnet:
                obs.append(Observation("same_subnet", [], {"subnet": subnet}))
            else:
                obs.append(Observation("other_subnet", [], {"subnet": subnet, "legit_subnet": legit_subnet}))
        if router == s.ident and router != legit_router:
            obs.append(Observation("self_gateway", [], {"ip": s.ident, "legit_router": legit_router}))
        if s.ident in s.dns and s.ident not in legit.dns:
            obs.append(Observation("self_dns"))
        if router == legit_router and dns == legit_dns:
            obs.append(Observation("same_options", [], {"router": router, "dns": dns, "legit": legit.ident}))
        faster = 0
        for ex in self.exchanges.values():
            times = {ident: ts for ident, ts in reversed(ex.offers)}
            if s.ident in times and legit.ident in times and times[s.ident] < times[legit.ident]:
                faster += 1
        if faster:
            obs.append(Observation("faster", [], {"count": faster}))
        victims = sorted(s.accepted)
        if victims:
            obs.append(Observation("accepted", [], {"count": len(victims)}))
        prefix = (s.mac or "")[:8]
        vendor = CONSUMER_ROUTER_OUIS.get(prefix)
        if vendor:
            obs.append(Observation("consumer_router", [], {"vendor": vendor}))
        vm = VM_OUIS.get(prefix)
        if vm:
            obs.append(Observation("vm_host", [], {"vendor": vm}))
        if s.relayed:
            obs.append(Observation("relay"))
        diagnosis = SERVERS.diagnose(obs, sufficient=s.offers + s.acks >= 2)
        pool = sorted(s.pool, key=lambda a: ipaddress.ip_address(a))
        pool_text = f"{pool[0]} to {pool[-1]}" if len(pool) > 1 else (pool[0] if pool else "none")
        frames = s.frames + [f for ex in self.exchanges.values() if any(i == s.ident for i, _ in ex.offers)
                             for f in ex.frames[:2]]
        ctx_text = {
            "ip": s.ident, "mac": s.mac or "unknown MAC", "router": router, "dns": dns, "pool": pool_text,
            "subnet": subnet, "legit": legit.ident, "legit_router": legit_router, "legit_subnet": legit_subnet,
            "accepted": len(victims), "victims": ", ".join(victims[:3]) or "the affected devices",
            "dns_part": " and DNS server" if s.ident in s.dns else "",
            "race": f" Its offers beat the legitimate server's {faster} time(s)." if faster else "",
            "vendor_note": f", a {vendor} device" if vendor else "",
        }
        impact = "critical_asset" if diagnosis.verdict == Verdict.ATTACK else "multi_host"
        return build_finding(
            analyzer=self.name, diagnosis=diagnosis, narratives=SERVER_TEXT, ctx=ctx_text,
            entities=[Entity(kind="ip", value=s.ident, role="DHCP server")]
            + ([Entity(kind="mac", value=s.mac, role="DHCP server")] if s.mac else [])
            + [Entity(kind="ip", value=legit.ident, role="legitimate DHCP server")]
            + [Entity(kind="mac", value=v, role="client") for v in victims[:5]],
            frames=frames, key_packets=s.kp + legit.kp[:2], time_start=s.first_ts, time_end=s.last_ts,
            wireshark_filter=f"dhcp.option.dhcp_server_id == {s.ident}",
            impact=impact, max_frames=self.limits.max_evidence_frames,
        )

    def _no_offer(self, ctx: Context) -> list[Finding]:
        lonely = [ex for ex in self.exchanges.values() if ex.discovers >= 2 and not ex.offers]
        if not lonely:
            return []
        count = sum(ex.discovers for ex in lonely)
        macs = sorted({ex.chaddr for ex in lonely if ex.chaddr})
        obs = [Observation("repeated", [f for ex in lonely for f in ex.frames], {"count": count},
                           strength=min(1.0, count / 4))]
        if len(macs) >= 2:
            obs.append(Observation("clients", [], {"count": len(macs)}))
        if not any(s.offers or s.acks for s in self.servers.values()):
            obs.append(Observation("no_server"))
        if ctx.gateway_silent():
            obs.append(Observation("silent_capture"))
        diagnosis = NO_OFFER.diagnose(obs, sufficient=count >= 3)
        first = min(ex.first_ts for ex in lonely)
        return [build_finding(
            analyzer=self.name, diagnosis=diagnosis, narratives=NO_OFFER_TEXT,
            ctx={"clients": len(macs) or 1, "count": count, "macs": ", ".join(macs[:4]),
                 "first": fmt_time(first), "last": fmt_time(ctx.last_ts or first)},
            entities=[Entity(kind="mac", value=m, role="client without address") for m in macs[:6]],
            frames=[f for ex in lonely for f in ex.frames], key_packets=[k for ex in lonely for k in ex.kp][:6],
            time_start=first, time_end=max(ex.first_ts for ex in lonely),
            wireshark_filter="dhcp.option.dhcp == 1",
            impact="multi_host" if len(macs) >= 2 else "single_host",
            max_frames=self.limits.max_evidence_frames,
        )]
