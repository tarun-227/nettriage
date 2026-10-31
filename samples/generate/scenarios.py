"""Labelled scenario captures, for the sample gallery and for accuracy testing.

    python samples/generate/scenarios.py                    # curated set, seed 1 -> samples/scenarios
    python samples/generate/scenarios.py --split dev        # seeds 1-3   -> eval/generated/dev (tuning)
    python samples/generate/scenarios.py --split holdout    # seeds 101-105 -> eval/generated/holdout (reporting)
    python samples/generate/scenarios.py --only arp_spoof_mitm --seeds 7

Each capture gets a sidecar <name>.labels.json with the ground truth: the
findings a correct analyser must raise, and nothing else. Hard negatives
expect no alerts at all.
"""

from __future__ import annotations

import argparse
import json
import random
import string
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from lan import BCAST, SITES, TS0, ZERO_MAC, Host, Lan
from scapy.all import ARP, ICMP, IP, TCP, Ether, Raw
from scapy.layers.vrrp import VRRP

ROOT = Path(__file__).resolve().parents[2]
DURATION = 60.0
ATTACKER_MAC = "08:00:27:3e:5a:11"  # VirtualBox OUI, a typical attacker VM
SPLITS = {"curated": [1], "dev": [1, 2, 3], "holdout": [101, 102, 103, 104, 105]}


@dataclass
class Scenario:
    name: str
    category: str  # attack, fault, negative, mixed
    title: str
    description: str
    build: Callable


SCENARIOS: dict[str, Scenario] = {}


def scenario(category: str, title: str, description: str):
    def register(fn):
        SCENARIOS[fn.__name__] = Scenario(fn.__name__, category, title, description, fn)
        return fn
    return register


class Result:
    def __init__(self, lan: Lan):
        self.lan = lan
        self.labels: list[dict] = []
        self.quality: list[str] = []
        self.incidents: list[list[str]] = []  # finding kinds that must be linked into one incident

    def expect(self, kind: str, verdict: str, entities: list[str], start: float, end: float = DURATION) -> None:
        self.labels.append({"kind": kind, "verdict": verdict, "entities": entities,
                            "start": round(TS0 + start, 3), "end": round(TS0 + end, 3)})

    def connect(self, *kinds: str) -> None:
        self.incidents.append(list(kinds))


def office(seed: int, n_clients: int = 6, dhcp_baseline: bool = True) -> tuple[Lan, random.Random]:
    rng = random.Random(seed)
    lan = Lan(rng, n_clients)
    if dhcp_baseline:
        c = lan.clients[0]
        lan.dhcp_dora(0.2, c.mac, c.ip)  # one renewal, so the legitimate server is visible
    return lan, rng


def lan_attacker(lan: Lan, browse: bool = True) -> Host:
    a = lan.host(f"{lan.subnet}.66", ATTACKER_MAC, "unknown-device")
    lan.arp_exchange(1.0, a, lan.gw)
    if browse:
        lan.background(DURATION, intensity=0.3, clients=[a])
    return a


# --- building blocks for attacks ----------------------------------------

def arp_poison(lan: Lan, attacker: Host, victim: Host, start: float, both_ways: bool, period: float = 2.0) -> None:
    """arpspoof-style unsolicited replies, repeated every couple of seconds."""
    t = start
    while t < DURATION:
        lan.trace.add(t, Ether(src=attacker.mac, dst=victim.mac) / ARP(
            op=2, hwsrc=attacker.mac, psrc=lan.gw.ip, hwdst=victim.mac, pdst=victim.ip))
        if both_ways:
            lan.trace.add(t + 0.0002, Ether(src=attacker.mac, dst=lan.gw.mac) / ARP(
                op=2, hwsrc=attacker.mac, psrc=victim.ip, hwdst=lan.gw.mac, pdst=lan.gw.ip))
        t += period + lan.rng.uniform(-0.05, 0.05)


def relay_through(lan: Lan, victim: Host, attacker: Host, start: float, both_ways: bool) -> None:
    """Rewrite the victim's traffic so it passes through the attacker, as IP forwarding would."""
    out = []
    for t, p in lan.trace.items:
        if t >= start and IP in p:
            e = p[Ether]
            outbound = e.src == victim.mac and e.dst == lan.gw.mac
            inbound = both_ways and e.src == lan.gw.mac and e.dst == victim.mac
            if outbound or inbound:
                first = p.copy()
                first[Ether].dst = attacker.mac
                second = p.copy()
                second[Ether].src = attacker.mac
                second[IP].ttl = max(1, p[IP].ttl - 1)
                del second[IP].chksum
                out.append((t, first))
                out.append((t + lan.rng.uniform(0.0002, 0.0008), second))
                continue
        out.append((t, p))
    lan.trace.items = out


def tcp_probes(lan: Lan, attacker: Host, target_ip: str, target_mac: str, start: float, ports: list[int],
               open_ports: set[int], flags: str = "S", step: tuple[float, float] = (0.001, 0.006),
               responds: bool = True, target_ttl: int = 64) -> float:
    rng = lan.rng
    sport = rng.randrange(40000, 65000)
    t = start
    for port in ports:
        t += rng.uniform(*step)
        seq = rng.getrandbits(32)
        opts = [("MSS", 1460)] if flags == "S" else []
        lan.trace.add(t, Ether(src=attacker.mac, dst=target_mac) / IP(
            src=attacker.ip, dst=target_ip, ttl=rng.choice([39, 44, 51, 58]), id=rng.randrange(65536)) / TCP(
            sport=sport, dport=port, flags=flags, seq=seq, window=1024, options=opts))
        if not responds:
            continue
        rt = t + rng.uniform(0.0002, 0.0012)
        back = Ether(src=target_mac, dst=attacker.mac) / IP(src=target_ip, dst=attacker.ip, ttl=target_ttl)
        if port in open_ports:
            if flags == "S":
                lan.trace.add(rt, back / TCP(sport=port, dport=sport, flags="SA", seq=rng.getrandbits(32),
                                             ack=seq + 1, window=64240, options=[("MSS", 1460)]))
                lan.trace.add(rt + 0.0002, Ether(src=attacker.mac, dst=target_mac) / IP(
                    src=attacker.ip, dst=target_ip, ttl=64) / TCP(sport=sport, dport=port, flags="R", seq=seq + 1))
            # stealth probes to open ports get no answer
        else:
            consumed = 1 if ("S" in flags or "F" in flags) else 0
            lan.trace.add(rt, back / TCP(sport=port, dport=sport, flags="RA", seq=0, ack=seq + consumed, window=0))
    return t


COMMON_PORTS = [21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 514, 587, 631,
                993, 995, 1080, 1433, 1521, 1723, 2049, 2121, 3000, 3128, 3306, 3389, 5000, 5060, 5432, 5900,
                6379, 8000, 8008, 8080, 8443, 8888, 9000, 9090, 9200, 27017]


def scan_ports(rng: random.Random, n: int, include: set[int]) -> list[int]:
    pool = sorted(set(COMMON_PORTS) | set(rng.sample(range(1, 10000), n * 2)))
    ports = list(include) + rng.sample([p for p in pool if p not in include], n - len(include))
    rng.shuffle(ports)
    return ports


def nas(lan: Lan) -> Host:
    return lan.host(f"{lan.subnet}.50", "00:11:32:aa:bb:50", "nas")


# --- attacks ------------------------------------------------------------

@scenario("attack", "ARP spoofing: two-way man-in-the-middle",
          "A device on the LAN tells one PC that it is the router, and tells the router that it is that PC. "
          "All of the PC's traffic now flows through the attacker, who forwards it so nothing looks broken.")
def arp_spoof_mitm(seed: int) -> Result:
    lan, rng = office(seed)
    attacker = lan_attacker(lan)
    victim = lan.clients[2]
    lan.background(DURATION)
    start = rng.uniform(18, 26)
    arp_poison(lan, attacker, victim, start, both_ways=True)
    relay_through(lan, victim, attacker, start, both_ways=True)
    # The real router still answers when the victim asks, so the binding flips back and forth.
    for t in (start + 14, start + 29):
        lan.arp_exchange(t, victim, lan.gw)
    r = Result(lan)
    r.expect("arp_spoofing", "attack", [lan.gw.ip, attacker.mac], start)
    return r


@scenario("attack", "ARP spoofing: one-way interception",
          "Only the victim PC is poisoned: its outgoing traffic goes through the attacker, replies come back "
          "directly. Common with simple tools such as arpspoof.")
def arp_spoof_oneway(seed: int) -> Result:
    lan, rng = office(seed)
    attacker = lan_attacker(lan)
    victim = lan.clients[1]
    lan.background(DURATION)
    start = rng.uniform(15, 30)
    arp_poison(lan, attacker, victim, start, both_ways=False, period=rng.choice([1.0, 2.0, 5.0]))
    relay_through(lan, victim, attacker, start, both_ways=False)
    lan.arp_exchange(start + 20, victim, lan.gw)
    r = Result(lan)
    r.expect("arp_spoofing", "attack", [lan.gw.ip, attacker.mac], start)
    return r


@scenario("attack", "Port scan: SYN scan of a file server",
          "A device probes a few hundred ports on the office NAS, as `nmap -sS` does, looking for services "
          "to attack. Open ports answer, closed ports reset.")
def port_scan_syn(seed: int) -> Result:
    lan, rng = office(seed)
    attacker = lan_attacker(lan)
    server = nas(lan)
    lan.background(DURATION)
    start = rng.uniform(15, 30)
    lan.arp_exchange(start - 0.01, attacker, server)
    ports = scan_ports(rng, rng.choice([150, 300, 600]), {22, 80, 443, 445})
    end = tcp_probes(lan, attacker, server.ip, server.mac, start, ports, {22, 80, 443, 445})
    r = Result(lan)
    r.expect("port_scan", "attack", [attacker.ip], start, end)
    return r


@scenario("attack", "Port scan: stealth Xmas scan",
          "Probes with the FIN, PSH and URG flags set at once, a combination normal TCP never sends. Closed "
          "ports reset, open ports stay silent.")
def port_scan_xmas(seed: int) -> Result:
    lan, rng = office(seed)
    attacker = lan_attacker(lan)
    server = nas(lan)
    lan.background(DURATION)
    start = rng.uniform(15, 30)
    lan.arp_exchange(start - 0.01, attacker, server)
    ports = scan_ports(rng, 120, {22, 80, 443})
    end = tcp_probes(lan, attacker, server.ip, server.mac, start, ports, {22, 80, 443}, flags="FPU")
    r = Result(lan)
    r.expect("port_scan", "attack", [attacker.ip], start, end)
    return r


@scenario("attack", "Port scan: sweep of another network",
          "An infected PC sweeps a whole /24 for SSH and Remote Desktop. Most addresses never answer.")
def port_scan_horizontal(seed: int) -> Result:
    lan, rng = office(seed)
    scanner = lan.clients[3]
    lan.background(DURATION)
    start = rng.uniform(10, 25)
    t = start
    for port in (22, 3389):
        for i in rng.sample(range(1, 255), 254):
            target = f"10.20.0.{i}"
            alive = rng.random() < 0.12
            opened = {port} if alive and rng.random() < 0.4 else set()
            t = tcp_probes(lan, scanner, target, lan.gw.mac, t, [port], opened, responds=alive,
                           step=(0.002, 0.012), target_ttl=60)
    r = Result(lan)
    r.expect("port_scan", "attack", [scanner.ip], start, t)
    return r


@scenario("attack", "Port scan: slow scan",
          "A patient attacker probes one port every second or two to slip under rate-based alarms. "
          "NetTriage's sequential test does not care about rate, only about how often first contacts fail.")
def port_scan_slow(seed: int) -> Result:
    lan, rng = office(seed)
    attacker = lan_attacker(lan)
    server = nas(lan)
    lan.background(DURATION)
    start = rng.uniform(3, 8)
    lan.arp_exchange(start - 0.01, attacker, server)
    ports = scan_ports(rng, 35, {22, 445})
    end = tcp_probes(lan, attacker, server.ip, server.mac, start, ports, {22, 445}, step=(1.0, 1.8))
    r = Result(lan)
    r.expect("port_scan", "attack", [attacker.ip], start, end)
    return r


@scenario("attack", "DNS spoofing: forged answers race the real resolver",
          "An attacker on the Wi-Fi sees a PC's DNS questions and answers them first, pointing the mail and "
          "university sites at itself. The real answers arrive a few milliseconds later and are ignored.")
def dns_spoof_race(seed: int) -> Result:
    lan, rng = office(seed)
    lan.resolver = lan.host("8.8.8.8", lan.gw.mac, "public-dns")
    lan.resolver_ttl = 117
    attacker = lan_attacker(lan)
    victim = lan.clients[1]
    lan.background(DURATION)
    targets = ["mail.example.org", "www.iiitdm.ac.in"]
    first = None
    for k in range(rng.choice([4, 6, 8])):
        t = rng.uniform(12, DURATION - 3)
        first = t if first is None else min(first, t)
        name = targets[k % 2]
        txid, sport = rng.randrange(65536), rng.randrange(49152, 65535)
        lan.ensure_arp(t, victim, lan.gw)
        lan.trace.add(t, lan.dns_query_pkt(victim, lan.resolver.ip, lan.gw.mac, name, txid, sport))
        lan.trace.add(t + rng.uniform(0.0004, 0.0015), lan.dns_response_pkt(
            lan.resolver.ip, attacker.mac, victim, name, txid, sport, [attacker.ip], ttl=3600, ip_ttl=64))
        lan.trace.add(t + rng.uniform(0.012, 0.04), lan.dns_response_pkt(
            lan.resolver.ip, lan.gw.mac, victim, name, txid, sport, [SITES[name]], ttl=300, ip_ttl=117))
        lan.tcp_session(t + 0.02, victim, attacker.ip, 443, rtt=rng.uniform(0.0005, 0.002), server_mac=attacker.mac,
                        server_ttl=64)
    r = Result(lan)
    r.expect("dns_spoofing", "attack", targets + [attacker.mac], first or 12)
    return r


@scenario("attack", "Rogue DHCP server",
          "A device answers DHCP faster than the real router and hands new laptops an address in the right "
          "subnet, but names itself as their gateway and DNS server. They keep working while it watches "
          "everything.")
def rogue_dhcp(seed: int) -> Result:
    lan, rng = office(seed)
    rogue = lan_attacker(lan)
    lan.background(DURATION)
    first = None
    for k in range(rng.choice([3, 4, 5])):
        t = rng.uniform(8, 40)
        first = t if first is None else min(first, t)
        mac = f"f4:8c:50:{k:02x}:{rng.randrange(256):02x}:{rng.randrange(256):02x}"
        xid = rng.getrandbits(32)
        rogue_ip, legit_ip = f"{lan.subnet}.{200 + k}", f"{lan.subnet}.{100 + k}"
        lan.dhcp_discover(t, mac, xid, hostname=f"laptop-{k}")
        lan.dhcp_offer(t + rng.uniform(0.001, 0.002), rogue.ip, rogue.mac, mac, xid, rogue_ip, rogue.ip, [rogue.ip])
        lan.dhcp_offer(t + rng.uniform(0.004, 0.009), lan.gw.ip, lan.gw.mac, mac, xid, legit_ip, lan.gw.ip,
                       [lan.gw.ip])
        lan.dhcp_request(t + 0.012, mac, xid, rogue_ip, rogue.ip)
        lan.dhcp_offer(t + 0.014, rogue.ip, rogue.mac, mac, xid, rogue_ip, rogue.ip, [rogue.ip], kind="ack")
        joiner = lan.host(rogue_ip, mac, f"laptop-{k}")
        tt = t + 0.5
        for _ in range(rng.randrange(3, 7)):
            name = rng.choice(list(SITES))
            ta = lan.dns_lookup(tt, joiner, name, resolver=rogue, rtt=rng.uniform(0.01, 0.04))
            lan.tcp_session(ta + 0.001, joiner, SITES[name], 443, server_mac=rogue.mac)
            tt += rng.uniform(1.5, 5)
    r = Result(lan)
    r.expect("rogue_dhcp", "attack", [rogue.ip, rogue.mac], first or 8)
    return r


# --- faults -------------------------------------------------------------

@scenario("fault", "Duplicate IP address",
          "Someone gave a new laptop a static address that a PC already uses. Both machines now answer for "
          "the same IP, so connections to it break at random.")
def duplicate_ip(seed: int) -> Result:
    lan, rng = office(seed)
    owner = lan.clients[4]
    lan.background(DURATION)
    t0 = rng.uniform(15, 30)
    intruder = lan.host(owner.ip, "f0:de:f1:3c:77:01", "new-laptop")
    # RFC 5227 probes from the newcomer; the current owner defends its address.
    for k in range(3):
        lan.trace.add(t0 + k, Ether(src=intruder.mac, dst=BCAST) / ARP(
            op=1, hwsrc=intruder.mac, psrc="0.0.0.0", hwdst=ZERO_MAC, pdst=owner.ip))
    lan.arp_reply(t0 + 0.0008, owner.mac, owner.ip, intruder)
    lan.gratuitous_arp(t0 + 3, owner.ip, intruder.mac)  # static config ignores the conflict
    others = [c for c in lan.clients if c is not owner] + [lan.gw]
    t = t0 + 4
    while t < DURATION:
        asker = rng.choice(others)
        lan.arp_request(t, asker, owner.ip)
        lan.arp_reply(t + rng.uniform(0.0003, 0.001), owner.mac, owner.ip, asker)
        lan.arp_reply(t + rng.uniform(0.001, 0.003), intruder.mac, owner.ip, asker)
        t += rng.uniform(3, 9)
    lan.background(DURATION - t0 - 4, start=t0 + 4, intensity=0.6, clients=[intruder])
    r = Result(lan)
    r.expect("duplicate_ip", "fault", [owner.ip], t0)
    return r


def _sites(*names: str) -> dict[str, str]:
    return {n: SITES[n] for n in names}


@scenario("fault", "Packet loss on the path to one server",
          "Every PC sees retransmissions, but only when talking to one content server: the problem is that "
          "server or the path to it, not the office network.")
def tcp_loss_path(seed: int) -> Result:
    lan, rng = office(seed)
    bad = SITES["cdn.example.net"]
    lan.background(DURATION, sites=_sites("cdn.example.net", "example.com", "github.com", "www.wikipedia.org"),
                   loss_for=lambda c, ip: (0.10, 0.06) if ip == bad else (0.0, 0.0))
    r = Result(lan)
    r.expect("tcp_retransmissions", "fault", [bad], 0)
    return r


@scenario("fault", "Packet loss on one PC's connection",
          "One PC loses packets to every server while the others are fine: a bad cable, a weak Wi-Fi signal "
          "or a failing network card on that machine.")
def tcp_loss_client(seed: int) -> Result:
    lan, rng = office(seed)
    bad = lan.clients[3]
    lan.background(DURATION, loss_for=lambda c, ip: (0.09, 0.0, "lan") if c is bad else (0.0, 0.0))
    r = Result(lan)
    r.expect("tcp_retransmissions", "fault", [bad.ip], 0)
    return r


@scenario("fault", "Service refusing connections",
          "The office app server is up, but the app on port 8080 has stopped: every connection is refused "
          "straight away. PCs keep retrying.")
def refused_service(seed: int) -> Result:
    lan, rng = office(seed)
    server = lan.host(f"{lan.subnet}.50", "00:15:5d:01:02:50", "app-server")
    lan.background(DURATION)
    first = None
    for _ in range(rng.randrange(15, 30)):
        c = rng.choice(lan.clients)
        t = rng.uniform(5, DURATION - 3)
        first = t if first is None else min(first, t)
        lan.ensure_arp(t, c, server)
        sport = rng.randrange(49152, 65535)
        seq = rng.getrandbits(32)
        for k in range(3):  # Windows retries a refused SYN twice
            ts = t + k * 0.5
            lan.trace.add(ts, lan.ip(c, server.ip, server.mac) / TCP(sport=sport, dport=8080, flags="S", seq=seq,
                                                                    options=[("MSS", 1460)]))
            lan.trace.add(ts + 0.0004, Ether(src=server.mac, dst=c.mac) / IP(src=server.ip, dst=c.ip, ttl=128) / TCP(
                sport=8080, dport=sport, flags="RA", seq=0, ack=seq + 1, window=0))
    r = Result(lan)
    r.expect("connection_refused", "fault", [server.ip], first or 5)
    return r


@scenario("fault", "Remote service not answering",
          "A cloud file service resolves fine, but connections to it get no reply at all. PCs retry with "
          "growing delays until they give up.")
def unreachable_remote(seed: int) -> Result:
    lan, rng = office(seed)
    dead = "203.0.113.99"
    lan.background(DURATION)
    first = None
    for c in rng.sample(lan.clients, 4):
        for _ in range(rng.randrange(1, 4)):
            t = rng.uniform(5, DURATION - 10)
            first = t if first is None else min(first, t)
            ta = lan.dns_lookup(t, c, "files.example.com", answers=[dead])
            sport, seq = rng.randrange(49152, 65535), rng.getrandbits(32)
            for delay in (0.0, 1.0, 3.0, 7.0):
                lan.trace.add(ta + 0.001 + delay, lan.ip(c, dead, lan.gw.mac) / TCP(
                    sport=sport, dport=443, flags="S", seq=seq, options=[("MSS", 1460)]))
    r = Result(lan)
    r.expect("host_unreachable", "fault", [dead], first or 5)
    return r


@scenario("fault", "Office printer switched off",
          "PCs keep asking 'who has 192.168.1.60?' and nobody answers: the device is off or unplugged.")
def unreachable_lan_host(seed: int) -> Result:
    lan, rng = office(seed)
    printer = f"{lan.subnet}.60"
    lan.background(DURATION)
    first = None
    for _ in range(rng.randrange(4, 9)):
        c = rng.choice(lan.clients)
        t = rng.uniform(3, DURATION - 4)
        first = t if first is None else min(first, t)
        for k in range(3):
            lan.arp_request(t + k, c, printer)
    r = Result(lan)
    r.expect("host_unreachable", "fault", [printer], first or 3)
    return r


@scenario("fault", "Very slow server",
          "Connections to one news site take most of a second just to start, while everything else is quick.")
def high_latency(seed: int) -> Result:
    lan, rng = office(seed)
    slow = SITES["news.example.net"]
    lan.background(DURATION, sites=_sites("news.example.net", "example.com", "github.com", "www.wikipedia.org"),
                   rtt_for=lambda ip: rng.uniform(0.6, 0.95) if ip == slow else None)
    r = Result(lan)
    r.expect("high_latency", "fault", [slow], 0)
    return r


def _failing_after(lan: Lan, rng: random.Random, t0: float, fail):
    def resolve(t, c, name):
        if t < t0:
            return lan.dns_lookup(t, c, name, answers=[SITES[name]]), SITES[name]
        return fail(t, c, name), None
    return resolve


@scenario("fault", "DNS server failing (SERVFAIL)",
          "Partway through, the router's DNS starts answering every question with 'server failure': its "
          "upstream is broken. Websites stop loading even though the network is up.")
def dns_servfail(seed: int) -> Result:
    lan, rng = office(seed)
    t0 = rng.uniform(15, 25)

    def fail(t, c, name):
        t1 = lan.dns_lookup(t, c, name, rcode=2, rtt=rng.uniform(0.05, 0.4))
        lan.dns_lookup(t1 + 1.0, c, name, rcode=2, rtt=rng.uniform(0.05, 0.4))
        return t1 + 1.5

    lan.background(DURATION, resolve=_failing_after(lan, rng, t0, fail))
    r = Result(lan)
    r.expect("dns_failure", "fault", [lan.resolver.ip], t0)
    return r


@scenario("fault", "DNS server not answering",
          "Partway through, the DNS server goes silent. PCs repeat every question and give up.")
def dns_timeout(seed: int) -> Result:
    lan, rng = office(seed)
    t0 = rng.uniform(15, 25)

    def fail(t, c, name):
        txid, sport = rng.randrange(65536), rng.randrange(49152, 65535)
        for delay in (0.0, 1.0, 3.0):
            lan.dns_lookup(t + delay, c, name, respond=False, txid=txid, sport=sport)
        return t + 5

    lan.background(DURATION, resolve=_failing_after(lan, rng, t0, fail))
    r = Result(lan)
    r.expect("dns_failure", "fault", [lan.resolver.ip], t0)
    return r


@scenario("fault", "Slow DNS",
          "The DNS server still answers, but each answer takes one to two and a half seconds, so every new "
          "website feels sluggish.")
def dns_slow(seed: int) -> Result:
    lan, rng = office(seed)
    t0 = rng.uniform(10, 20)

    def resolve(t, c, name):
        rtt = rng.uniform(0.8, 2.5) if t >= t0 else None
        return lan.dns_lookup(t, c, name, answers=[SITES[name]], rtt=rtt), SITES[name]

    lan.background(DURATION, resolve=resolve)
    r = Result(lan)
    r.expect("dns_slow", "fault", [lan.resolver.ip], t0)
    return r


@scenario("fault", "Internet connection down",
          "Partway through, the office's internet line drops. The router's DNS starts failing and every PC's "
          "connections to sites it already knew go unanswered. Many failed connections from every PC: an outage, "
          "not a port scan.")
def uplink_outage(seed: int) -> Result:
    lan, rng = office(seed)
    t0 = rng.uniform(20, 30)
    cache: dict[tuple[str, str], str] = {}

    def resolve(t, c, name):
        if t < t0:
            cache[(c.ip, name)] = SITES[name]
            return lan.dns_lookup(t, c, name, answers=[SITES[name]]), SITES[name]
        ip = cache.get((c.ip, name))
        if ip:  # cached name: the PC tries to connect straight away and gets nothing back
            sport, seq = rng.randrange(49152, 65535), rng.getrandbits(32)
            for delay in (0.0, 1.0, 3.0):
                lan.trace.add(t + delay, lan.ip(c, ip, lan.gw.mac) / TCP(sport=sport, dport=443, flags="S", seq=seq,
                                                                        options=[("MSS", 1460)]))
            return t + 7, None
        return lan.dns_lookup(t, c, name, rcode=2, rtt=rng.uniform(0.5, 2.0)), None

    lan.background(DURATION, resolve=resolve)
    r = Result(lan)
    r.expect("connectivity_outage", "fault", [], t0)
    r.expect("dns_failure", "fault", [lan.resolver.ip], t0)
    r.connect("connectivity_outage", "dns_failure")
    return r


def upload(lan: Lan, rng: random.Random, t: float, c: Host, server_ip: str, *, icmp_from: str | None,
           path_mtu: int = 1400, chunks: int = 6, windows_fallback: bool = False) -> float:
    """A client upload over a path whose MTU is smaller than its own.

    With ``icmp_from`` the bottleneck router reports "fragmentation needed" and the
    client resends in smaller segments (PMTUD working). Without it the ICMP is
    filtered: full-size segments vanish and are retransmitted until the client
    gives up, or, like Windows' black-hole detection, falls back to 536-byte segments.
    """
    sport, cseq, sseq = rng.randrange(49152, 65535), rng.getrandbits(32), rng.getrandbits(32)
    rtt, dport = rng.uniform(0.02, 0.05), 587

    def C(flags, seq, ack, n=0):
        p = lan.ip(c, server_ip, lan.gw.mac) / TCP(sport=sport, dport=dport, flags=flags, seq=seq & 0xFFFFFFFF,
                                                   ack=ack & 0xFFFFFFFF, window=64240)
        return p / Raw(b"\x00" * n) if n else p

    def S(flags, seq, ack, n=0):
        p = Ether(src=lan.gw.mac, dst=c.mac) / IP(src=server_ip, dst=c.ip, ttl=54, flags="DF") / TCP(
            sport=dport, dport=sport, flags=flags, seq=seq & 0xFFFFFFFF, ack=ack & 0xFFFFFFFF, window=65160)
        return p / Raw(b"\x00" * n) if n else p

    tr = lan.trace
    syn = C("S", cseq, 0)
    syn[TCP].options = [("MSS", 1460), ("NOP", None), ("WScale", 7), ("SAckOK", b"")]
    tr.add(t, syn)
    t += rtt
    synack = S("SA", sseq, cseq + 1)
    synack[TCP].options = [("MSS", 1460)]
    tr.add(t, synack)
    tr.add(t + 0.0003, C("A", cseq + 1, sseq + 1))
    s_next, c_next = sseq + 1, cseq + 1
    # A small greeting each way gets through fine.
    tr.add(t + 0.002, S("PA", s_next, c_next, 64))
    s_next += 64
    tr.add(t + 0.003, C("PA", c_next, s_next, 120))
    c_next += 120
    t += rtt + 0.003
    tr.add(t, S("A", s_next, c_next))
    big = 1448
    start = c_next
    first_big = None
    for i in range(chunks):
        pkt = C("PA" if i == chunks - 1 else "A", start + i * big, s_next, big)
        tr.add(t + 0.001 + i * 0.0004, pkt)
        if first_big is None:
            first_big = pkt
    t += 0.01
    if icmp_from:
        router = Ether(src=lan.gw.mac, dst=c.mac) / IP(src=icmp_from, dst=c.ip, ttl=62) / ICMP(
            type=3, code=4, nexthopmtu=path_mtu) / IP(src=c.ip, dst=server_ip, ttl=63, flags="DF") / TCP(
            sport=sport, dport=dport, flags="A", seq=start)
        tr.add(t + 0.004, router)
        seg = path_mtu - 40
        t += 0.01
        total, sent = chunks * big, 0
        while sent < total:
            n = min(seg, total - sent)
            tr.add(t, C("A", start + sent, s_next, n))
            sent += n
            t += 0.0005
            if sent % (2 * seg) == 0 or sent == total:
                tr.add(t + rtt, S("A", s_next, start + sent))
        t += rtt + 0.05
        tr.add(t, C("FA", start + total, s_next))
        tr.add(t + rtt, S("FA", s_next, start + total + 1))
        return t + rtt
    rto = 0.3
    for _ in range(5):
        t += rto
        tr.add(t, C("A", start, s_next, big))  # the same full-size segment, again and again
        rto *= 2
    if windows_fallback:
        sent, total = 0, chunks * big
        while sent < total:
            n = min(536, total - sent)
            t += 0.002
            tr.add(t, C("A", start + sent, s_next, n))
            sent += n
            tr.add(t + rtt, S("A", s_next, start + sent))
        return t + rtt
    tr.add(t + 2.0, C("RA", start, s_next))
    return t + 2.0


@scenario("fault", "Uploads hang: path MTU black hole",
          "After a VPN or PPPoE link was added, uploads to the mail server stall: small packets get through, "
          "full-size ones vanish, and the router's 'packet too big' message is blocked by a firewall.")
def pmtud_blackhole(seed: int) -> Result:
    lan, rng = office(seed)
    server = SITES["mail.example.org"]
    lan.background(DURATION)
    first = None
    for i, c in enumerate(rng.sample(lan.clients, rng.choice([2, 3, 4]))):
        t = rng.uniform(5, 30)
        first = t if first is None else min(first, t)
        lan.ensure_arp(t, c, lan.gw)
        upload(lan, rng, t, c, server, icmp_from=None, windows_fallback=i % 2 == 1)
    r = Result(lan)
    r.expect("mtu_blackhole", "fault", [server], first or 5)
    return r


@scenario("negative", "Smaller path MTU, handled correctly",
          "The route to the mail server has a smaller MTU (1400 bytes). The router says so with an ICMP "
          "'fragmentation needed' message, the PCs shrink their packets, and every upload completes. "
          "Nothing is broken.")
def mtu_small_path(seed: int) -> Result:
    lan, rng = office(seed)
    server = SITES["mail.example.org"]
    lan.background(DURATION)
    for c in rng.sample(lan.clients, rng.choice([2, 3, 4])):
        t = rng.uniform(5, 40)
        lan.ensure_arp(t, c, lan.gw)
        upload(lan, rng, t, c, server, icmp_from="100.64.12.1", path_mtu=rng.choice([1400, 1420, 1452]))
    return Result(lan)


@scenario("attack", "Man-in-the-middle with forged DNS",
          "One device poisons ARP to sit between a PC and the router, then uses its position to answer that "
          "PC's DNS questions for the bank and mail sites with its own address. Two findings, one attacker.")
def mitm_dns_combo(seed: int) -> Result:
    lan, rng = office(seed)
    attacker = lan_attacker(lan)
    victim = lan.clients[2]
    lan.background(DURATION)
    start = rng.uniform(12, 20)
    arp_poison(lan, attacker, victim, start, both_ways=True)
    targets = ["mail.example.org", "www.iiitdm.ac.in"]
    first = None
    for k in range(rng.choice([3, 4, 5])):
        t = rng.uniform(start + 3, DURATION - 4)
        first = t if first is None else min(first, t)
        name = targets[k % 2]
        txid, sport = rng.randrange(65536), rng.randrange(49152, 65535)
        lan.trace.add(t, lan.dns_query_pkt(victim, lan.gw.ip, lan.gw.mac, name, txid, sport))
        lan.trace.add(t + rng.uniform(0.0004, 0.0012), lan.dns_response_pkt(
            lan.gw.ip, attacker.mac, victim, name, txid, sport, [attacker.ip], ttl=3600, ip_ttl=64))
        lan.trace.add(t + rng.uniform(0.012, 0.03), lan.dns_response_pkt(
            lan.gw.ip, lan.gw.mac, victim, name, txid, sport, [SITES[name]], ttl=300, ip_ttl=64))
    relay_through(lan, victim, attacker, start, both_ways=True)
    r = Result(lan)
    r.expect("arp_spoofing", "attack", [lan.gw.ip, attacker.mac], start)
    r.expect("dns_spoofing", "attack", targets + [attacker.mac], first or start)
    r.connect("arp_spoofing", "dns_spoofing")
    return r


@scenario("fault", "DHCP server down",
          "New laptops ask for an address again and again and nobody offers one, so they never get online.")
def dhcp_no_offer(seed: int) -> Result:
    lan, rng = office(seed, dhcp_baseline=False)
    lan.background(DURATION)
    first = None
    for k in range(rng.choice([2, 3])):
        t = rng.uniform(3, 20)
        first = t if first is None else min(first, t)
        mac = f"f4:8c:50:{k:02x}:{rng.randrange(256):02x}:{rng.randrange(256):02x}"
        xid = rng.getrandbits(32)
        for delay in (0, 4, 12, 28):
            if t + delay < DURATION:
                lan.dhcp_discover(t + delay, mac, xid, hostname=f"laptop-{k}")
    r = Result(lan)
    r.expect("dhcp_no_offer", "fault", [], first or 3)
    return r


@scenario("fault", "Home router plugged in by mistake",
          "Someone plugged a home Wi-Fi router into the office network by its LAN port. It hands out "
          "192.168.0.x addresses, and laptops that take one lose their connection.")
def misplugged_router(seed: int) -> Result:
    lan, rng = office(seed)
    home = lan.host("192.168.0.1", "c0:4a:00:2b:7d:10", "home-router")
    lan.background(DURATION)
    first = None
    for k in range(rng.choice([2, 3, 4])):
        t = rng.uniform(5, 40)
        first = t if first is None else min(first, t)
        mac = f"f4:8c:50:{k:02x}:{rng.randrange(256):02x}:{rng.randrange(256):02x}"
        xid = rng.getrandbits(32)
        bad_ip, good_ip = f"192.168.0.{100 + k}", f"{lan.subnet}.{100 + k}"
        lan.dhcp_discover(t, mac, xid, hostname=f"laptop-{k}")
        lan.dhcp_offer(t + rng.uniform(0.001, 0.003), home.ip, home.mac, mac, xid, bad_ip, home.ip, [home.ip])
        lan.dhcp_offer(t + rng.uniform(0.004, 0.009), lan.gw.ip, lan.gw.mac, mac, xid, good_ip, lan.gw.ip,
                       [lan.gw.ip])
        lan.dhcp_request(t + 0.012, mac, xid, bad_ip, home.ip)
        lan.dhcp_offer(t + 0.014, home.ip, home.mac, mac, xid, bad_ip, home.ip, [home.ip], kind="ack")
        joiner = lan.host(bad_ip, mac)
        lan.arp_exchange(t + 0.3, joiner, home)
    r = Result(lan)
    r.expect("dhcp_misconfigured_server", "fault", [home.ip], first or 5)
    return r


# --- hard negatives: things that look bad but are not --------------------

@scenario("negative", "Normal office traffic",
          "Six PCs browsing, with DNS lookups, HTTPS sessions, browsers resetting finished connections, and "
          "background chatter. Nothing is wrong.")
def clean_office(seed: int) -> Result:
    lan, rng = office(seed)
    lan.background(DURATION)
    return Result(lan)


@scenario("negative", "Router failover (VRRP)",
          "The office has two routers sharing one gateway address. The main one fails and the backup takes "
          "over, announcing the gateway address with its own MAC. It looks like ARP spoofing, but it is "
          "planned redundancy.")
def vrrp_failover(seed: int) -> Result:
    lan, rng = office(seed)
    r1 = lan.host(f"{lan.subnet}.2", "00:1b:21:aa:00:02", "router-a")
    r2 = lan.host(f"{lan.subnet}.3", "00:1b:21:aa:00:03", "router-b")
    lan.gw.mac = r1.mac
    t0 = rng.uniform(20, 35)
    lan.background(t0)
    lan.gw.mac = r2.mac
    lan.arp_cache.clear()
    for k in range(3):
        lan.gratuitous_arp(t0 + k * 1.0, lan.gw.ip, r2.mac)
    lan.background(DURATION - t0, start=t0 + 0.5)
    t = 0.0
    while t < DURATION:
        master = r1 if t < t0 - 3 else r2
        if t < t0 - 3 or t >= t0:
            lan.trace.add(t, Ether(src=master.mac, dst="01:00:5e:00:00:12") / IP(
                src=master.ip, dst="224.0.0.18", ttl=255, proto=112) / VRRP(
                vrid=1, priority=200 if master is r1 else 100, addrlist=[lan.gw.ip]))
        t += 1.0
    return Result(lan)


@scenario("negative", "Devices joining the network",
          "Three laptops join, get addresses by DHCP, check that nobody else uses them (ARP probes) and "
          "announce themselves. Textbook behaviour.")
def boot_announce(seed: int) -> Result:
    lan, rng = office(seed)
    lan.background(DURATION)
    for k in range(3):
        t = rng.uniform(5, 40)
        ip = f"{lan.subnet}.{40 + k}"
        mac = f"3c:22:fb:{k:02x}:{rng.randrange(256):02x}:{rng.randrange(256):02x}"
        lan.dhcp_dora(t, mac, ip)
        for j in range(3):
            lan.trace.add(t + 0.1 + j, Ether(src=mac, dst=BCAST) / ARP(op=1, hwsrc=mac, psrc="0.0.0.0",
                                                                   hwdst=ZERO_MAC, pdst=ip))
        for j in range(2):
            lan.gratuitous_arp(t + 3.2 + j * 2, ip, mac)
        lan.background(DURATION - t - 8, start=t + 8, clients=[lan.host(ip, mac)], intensity=0.6)
    return Result(lan)


@scenario("negative", "PC with a replaced network card",
          "A PC's network adapter is swapped. Its IP address moves to a new MAC once, after a fresh DHCP "
          "lease, and stays there. A single, explained change, not spoofing.")
def nic_swap(seed: int) -> Result:
    lan, rng = office(seed)
    c = lan.clients[2]
    t0 = rng.uniform(15, 25)
    lan.background(DURATION, clients=[x for x in lan.clients if x is not c])
    lan.background(t0, clients=[c])
    new = lan.host(c.ip, "9c:eb:e8:41:07:2c", c.name)
    lan.dhcp_dora(t0 + 8, new.mac, new.ip)
    lan.gratuitous_arp(t0 + 8.5, new.ip, new.mac)
    lan.background(DURATION - t0 - 9, start=t0 + 9, clients=[new])
    return Result(lan)


@scenario("negative", "Two DHCP servers in failover",
          "Two DHCP servers share the job and both answer, handing out different addresses with the same "
          "gateway and DNS. Redundant, not rogue.")
def dhcp_failover_pair(seed: int) -> Result:
    lan, rng = office(seed, dhcp_baseline=False)
    a = lan.host(f"{lan.subnet}.2", "00:15:5d:00:00:02", "dhcp-a")
    b = lan.host(f"{lan.subnet}.3", "00:15:5d:00:00:03", "dhcp-b")
    lan.background(DURATION)
    for k in range(rng.choice([3, 4, 5])):
        t = rng.uniform(3, 45)
        mac = f"f4:8c:50:{k:02x}:{rng.randrange(256):02x}:{rng.randrange(256):02x}"
        xid = rng.getrandbits(32)
        ia, ib = f"{lan.subnet}.{100 + k}", f"{lan.subnet}.{150 + k}"
        lan.dhcp_discover(t, mac, xid)
        da, db = rng.uniform(0.002, 0.006), rng.uniform(0.002, 0.006)
        lan.dhcp_offer(t + da, a.ip, a.mac, mac, xid, ia, lan.gw.ip, [lan.gw.ip])
        lan.dhcp_offer(t + db, b.ip, b.mac, mac, xid, ib, lan.gw.ip, [lan.gw.ip])
        win, ip = (a, ia) if da <= db else (b, ib)
        lan.dhcp_request(t + 0.01, mac, xid, ip, win.ip)
        lan.dhcp_offer(t + 0.012, win.ip, win.mac, mac, xid, ip, lan.gw.ip, [lan.gw.ip], kind="ack")
    return Result(lan)


BLOCKED = ["ads.example.com", "tracker.example.net", "telemetry.example.org"]


@scenario("negative", "Ad-blocking DNS (Pi-hole)",
          "The office DNS blocks ad and tracking domains by answering 0.0.0.0. Odd answers, but deliberate.")
def pihole_blocking(seed: int) -> Result:
    lan, rng = office(seed)
    sites = dict(SITES) | {n: "0.0.0.0" for n in BLOCKED}

    def resolve(t, c, name):
        if name in BLOCKED:
            return lan.dns_lookup(t, c, name, answers=["0.0.0.0"], ttl=2), None
        return lan.dns_lookup(t, c, name, answers=[SITES[name]]), SITES[name]

    lan.background(DURATION, sites=sites, resolve=resolve)
    return Result(lan)


@scenario("negative", "CDN address rotation",
          "A content network returns a different address almost every time it is asked, which is how load "
          "balancing works, not hijacking.")
def cdn_rotation(seed: int) -> Result:
    lan, rng = office(seed)
    pool = ["151.101.1.69", "151.101.65.69", "151.101.129.69", "151.101.193.69"]

    def resolve(t, c, name):
        if name == "cdn.example.net":
            ips = rng.sample(pool, rng.choice([1, 2]))
            return lan.dns_lookup(t, c, name, answers=ips, ttl=20), ips[0]
        return lan.dns_lookup(t, c, name, answers=[SITES[name]]), SITES[name]

    lan.background(DURATION, sites=_sites("cdn.example.net", "example.com", "github.com", "docs.python.org"),
                   resolve=resolve)
    return Result(lan)


@scenario("negative", "One very busy PC",
          "A developer's PC opens over a hundred connections to the same code-hosting site within seconds "
          "(a big download, many parallel requests). Lots of connections, but all to one place and all "
          "successful.")
def busy_client(seed: int) -> Result:
    lan, rng = office(seed)
    lan.background(DURATION)
    c = lan.clients[0]
    t = rng.uniform(10, 20)
    for _ in range(rng.randrange(100, 140)):
        lan.tcp_session(t, c, SITES["github.com"], 443, resp=rng.randrange(800, 3000), close="rst")
        t += rng.uniform(0.02, 0.08)
    return Result(lan)


@scenario("negative", "Normal failed lookups",
          "Browsers look up random names at startup to detect DNS hijacking, and Windows asks for wpad and "
          "isatap. These fail by design (NXDOMAIN).")
def nxdomain_probes(seed: int) -> Result:
    lan, rng = office(seed)
    for c in lan.clients:
        t = rng.uniform(0.5, 3)
        for _ in range(3):
            label = "".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randrange(7, 16)))
            lan.dns_lookup(t, c, label, rcode=3)
            t += rng.uniform(0.01, 0.1)
        for name in ("wpad.lan", "isatap.lan"):
            lan.dns_lookup(t, c, name, rcode=3)

    def resolve(t, c, name):
        if rng.random() < 0.04:
            return lan.dns_lookup(t, c, name + ".lan", rcode=3), None  # search-suffix miss
        return lan.dns_lookup(t, c, name, answers=[SITES[name]]), SITES[name]

    lan.background(DURATION, resolve=resolve)
    return Result(lan)


@scenario("negative", "One-directional capture",
          "The mirror port was set to copy only outgoing traffic. Every question looks unanswered, but the "
          "network is fine: the capture is incomplete. NetTriage should say so instead of blaming the network.")
def one_directional(seed: int) -> Result:
    lan, rng = office(seed)
    lan.background(DURATION)
    macs = {c.mac for c in lan.clients}
    lan.trace.items = [(t, p) for t, p in lan.trace.items if p[Ether].src in macs]
    r = Result(lan)
    r.quality.append("one_directional")
    return r


# --- mixed --------------------------------------------------------------

@scenario("mixed", "Lossy link and a port scan at the same time",
          "Retransmissions to one server (a fault) and a port scan from a LAN device (an attack) in the same "
          "capture. Both must be reported, each with the right label.")
def lossy_link_plus_scan(seed: int) -> Result:
    lan, rng = office(seed)
    bad = SITES["cdn.example.net"]
    attacker = lan_attacker(lan)
    server = nas(lan)
    lan.background(DURATION, sites=_sites("cdn.example.net", "example.com", "github.com", "www.wikipedia.org"),
                   loss_for=lambda c, ip: (0.10, 0.06) if ip == bad else (0.0, 0.0))
    start = rng.uniform(20, 35)
    lan.arp_exchange(start - 0.01, attacker, server)
    end = tcp_probes(lan, attacker, server.ip, server.mac, start, scan_ports(rng, 200, {22, 445}), {22, 445})
    r = Result(lan)
    r.expect("tcp_retransmissions", "fault", [bad], 0)
    r.expect("port_scan", "attack", [attacker.ip], start, end)
    return r


# --- driver -------------------------------------------------------------

def generate(names: list[str], seeds: list[int], out: Path, suffix_seed: bool) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name in names:
        sc = SCENARIOS[name]
        for seed in seeds:
            result = sc.build(seed)
            stem = f"{name}__s{seed}" if suffix_seed else name
            n = result.lan.trace.write(out / f"{stem}.pcap")
            meta = {"scenario": name, "category": sc.category, "title": sc.title, "description": sc.description,
                    "seed": seed, "packets": n, "labels": result.labels, "quality": result.quality,
                    "incidents": result.incidents}
            (out / f"{stem}.labels.json").write_text(json.dumps(meta, indent=2) + "\n")
            print(f"  {stem:40s} {n:>7,} packets  {len(result.labels)} label(s)")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--split", choices=sorted(SPLITS), default="curated")
    ap.add_argument("--seeds", help="comma-separated seeds, overrides --split")
    ap.add_argument("--only", help="comma-separated scenario names")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    names = args.only.split(",") if args.only else list(SCENARIOS)
    unknown = [n for n in names if n not in SCENARIOS]
    if unknown:
        ap.error(f"unknown scenario(s): {', '.join(unknown)}")
    seeds = [int(s) for s in args.seeds.split(",")] if args.seeds else SPLITS[args.split]
    if args.out:
        out = args.out
    elif args.split == "curated" and not args.seeds:
        out = ROOT / "samples" / "scenarios"
    else:
        out = ROOT / "eval" / "generated" / args.split
    generate(names, seeds, out, suffix_seed=not (args.split == "curated" and not args.seeds))


if __name__ == "__main__":
    main()
