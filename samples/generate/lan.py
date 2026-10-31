"""A small simulated office LAN that emits realistic background traffic.

Used only to generate labelled sample captures (Scapy is a dev dependency).
Everything is driven by a seeded RNG, so a (scenario, seed) pair always
produces the same file.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from pathlib import Path

from scapy.all import (
    ARP,
    BOOTP,
    DHCP,
    DNS,
    DNSQR,
    DNSRR,
    IP,
    TCP,
    UDP,
    Ether,
    Raw,
    conf,
)

conf.verb = 0

TS0 = 1_730_390_400.0  # 2024-10-31 16:00:00 UTC
SNAPLEN = 400
BCAST = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"

SITES = {
    "example.com": "93.184.216.34",
    "www.wikipedia.org": "208.80.154.224",
    "github.com": "140.82.112.3",
    "api.github.com": "140.82.112.6",
    "docs.python.org": "151.101.0.223",
    "www.iiitdm.ac.in": "14.139.181.229",
    "mail.example.org": "203.0.113.25",
    "news.example.net": "198.51.100.80",
    "cdn.example.net": "151.101.1.69",
    "updates.example.com": "192.0.2.44",
}


@dataclass
class Host:
    ip: str
    mac: str
    name: str = ""
    ip_id: int = 1  # Lan.host() seeds this from the scenario RNG

    def next_id(self) -> int:
        self.ip_id = (self.ip_id + 1) & 0xFFFF
        return self.ip_id


class Trace:
    """Timed packets, sorted on write."""

    def __init__(self) -> None:
        self.items: list[tuple[float, object]] = []

    def add(self, t: float, pkt) -> None:
        self.items.append((t, pkt))

    def sorted(self) -> list[tuple[float, object]]:
        return sorted(self.items, key=lambda x: x[0])

    def write(self, path) -> int:
        """Write with a 400-byte snap length, like `tcpdump -s 400`.

        ARP, DNS and DHCP fit whole; TCP payload beyond that is cut, which keeps
        the sample files small (the payload is filler anyway).
        """
        from nettriage.evidence.pcapwriter import pcap_bytes

        rows = []
        for t, p in self.sorted():
            raw = bytes(p)
            rows.append((int(round((TS0 + t) * 1e9)), raw[:SNAPLEN], len(raw)))
        Path(path).write_bytes(pcap_bytes(rows, linktype=1, snaplen=SNAPLEN))
        return len(rows)


class Lan:
    def __init__(self, rng: random.Random, n_clients: int = 8, subnet: str = "192.168.1"):
        self.rng = rng
        self.subnet = subnet
        self.gw = self.host(f"{subnet}.1", "3c:52:82:10:00:01", "router")
        self.resolver = self.gw  # small office: the router is the DNS resolver
        self.resolver_ttl = 64   # IP TTL of the resolver's replies as they reach the LAN
        self.clients = [
            self.host(f"{subnet}.{10 + i}",
                      f"a4:5e:60:{i:02x}:{rng.randrange(256):02x}:{rng.randrange(256):02x}", f"pc-{i + 1:02d}")
            for i in range(n_clients)
        ]
        self.trace = Trace()
        self.arp_cache: dict[tuple[str, str], float] = {}

    def host(self, ip: str, mac: str, name: str = "") -> Host:
        return Host(ip, mac, name, self.rng.randrange(1, 60000))

    # --- primitives -----------------------------------------------------

    def eth(self, src: Host | str, dst: Host | str):
        return Ether(src=src.mac if isinstance(src, Host) else src, dst=dst.mac if isinstance(dst, Host) else dst)

    def ip(self, src: Host, dst_ip: str, dst_mac: str, ttl: int = 64):
        return Ether(src=src.mac, dst=dst_mac) / IP(src=src.ip, dst=dst_ip, ttl=ttl, id=src.next_id(), flags="DF")

    def arp_request(self, t: float, who: Host, target_ip: str) -> None:
        self.trace.add(t, Ether(src=who.mac, dst=BCAST) / ARP(op=1, hwsrc=who.mac, psrc=who.ip, hwdst=ZERO_MAC,
                                                             pdst=target_ip))

    def arp_reply(self, t: float, owner_mac: str, owner_ip: str, to: Host) -> None:
        self.trace.add(t, Ether(src=owner_mac, dst=to.mac) / ARP(op=2, hwsrc=owner_mac, psrc=owner_ip,
                                                                hwdst=to.mac, pdst=to.ip))

    def arp_exchange(self, t: float, who: Host, target: Host) -> float:
        self.arp_request(t, who, target.ip)
        d = self.rng.uniform(0.0002, 0.002)
        self.arp_reply(t + d, target.mac, target.ip, who)
        return t + d

    def ensure_arp(self, t: float, who: Host, target: Host) -> None:
        last = self.arp_cache.get((who.ip, target.ip))
        if last is None or t - last > 60:
            self.arp_exchange(t - 0.003, who, target)
            self.arp_cache[(who.ip, target.ip)] = t

    def gratuitous_arp(self, t: float, host_ip: str, host_mac: str) -> None:
        self.trace.add(t, Ether(src=host_mac, dst=BCAST) / ARP(op=1, hwsrc=host_mac, psrc=host_ip,
                                                              hwdst=ZERO_MAC, pdst=host_ip))

    # --- DNS ------------------------------------------------------------

    def dns_query_pkt(self, c: Host, resolver_ip: str, resolver_mac: str, name: str, txid: int, sport: int,
                      qtype: str = "A"):
        return self.ip(c, resolver_ip, resolver_mac) / UDP(sport=sport, dport=53) / DNS(
            id=txid, rd=1, qd=DNSQR(qname=name, qtype=qtype))

    def dns_response_pkt(self, src_ip: str, src_mac: str, c: Host, name: str, txid: int, sport: int,
                         answers: list[str], rcode: int = 0, ttl: int = 300, qtype: str = "A", ip_id=None,
                         ip_ttl: int = 64):
        an = [DNSRR(rrname=name, type=qtype, rdata=a, ttl=ttl) for a in answers] or None
        return (Ether(src=src_mac, dst=c.mac)
                / IP(src=src_ip, dst=c.ip, ttl=ip_ttl, id=ip_id if ip_id is not None else self.rng.randrange(65536))
                / UDP(sport=53, dport=sport)
                / DNS(id=txid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=name, qtype=qtype), an=an))

    def dns_lookup(self, t: float, c: Host, name: str, answers: list[str] | None = None, rtt: float | None = None,
                   rcode: int = 0, respond: bool = True, ttl: int = 300, resolver: Host | None = None,
                   txid: int | None = None, sport: int | None = None) -> float:
        """Client asks the resolver; returns the time the answer arrives."""
        resolver = resolver or self.resolver
        txid = self.rng.randrange(65536) if txid is None else txid
        sport = self.rng.randrange(49152, 65535) if sport is None else sport
        rtt = self.rng.uniform(0.004, 0.035) if rtt is None else rtt
        self.ensure_arp(t, c, resolver)
        self.trace.add(t, self.dns_query_pkt(c, resolver.ip, resolver.mac, name, txid, sport))
        if respond:
            if answers is None:
                answers = [SITES.get(name, "192.0.2.1")] if rcode == 0 else []
            self.trace.add(t + rtt, self.dns_response_pkt(resolver.ip, resolver.mac, c, name, txid, sport,
                                                          answers, rcode, ttl, ip_ttl=self.resolver_ttl))
        return t + rtt

    # --- TCP ------------------------------------------------------------

    def tcp_session(self, t: float, c: Host, server_ip: str, dport: int, rtt: float | None = None,
                    server_mac: str | None = None, req: int = 400, resp: int | None = None,
                    down_loss: float = 0.0, up_loss: float = 0.0, close: str = "fin",
                    server_ttl: int = 54, mss: int = 1448, loss_side: str = "wan") -> float:
        """A complete client/server exchange as seen from a LAN mirror port.

        ``loss_side`` says where lost packets disappear relative to the mirror port:
        "wan" (between the office and the server) or "lan" (on the client's own link,
        so the mirror still sees the original before it is lost).
        """
        rng = self.rng
        rtt = rng.uniform(0.015, 0.06) if rtt is None else rtt
        server_mac = server_mac or self.gw.mac
        resp = rng.randrange(1500, 12000) if resp is None else resp
        sport = rng.randrange(49152, 65535)
        cseq, sseq = rng.getrandbits(32), rng.getrandbits(32)
        srv_id = [rng.randrange(65536)]

        def C(flags, seq, ack, payload=0, opts=None):
            p = self.ip(c, server_ip, server_mac) / TCP(sport=sport, dport=dport, flags=flags, seq=seq & 0xFFFFFFFF,
                                                        ack=ack & 0xFFFFFFFF, window=64240,
                                                        options=opts or [])
            return p / Raw(b"\x17" * payload) if payload else p

        def S(flags, seq, ack, payload=0, opts=None):
            srv_id[0] = (srv_id[0] + 1) & 0xFFFF
            p = (Ether(src=server_mac, dst=c.mac) / IP(src=server_ip, dst=c.ip, ttl=server_ttl, id=srv_id[0],
                                                        flags="DF")
                 / TCP(sport=dport, dport=sport, flags=flags, seq=seq & 0xFFFFFFFF, ack=ack & 0xFFFFFFFF,
                       window=65160, options=opts or []))
            return p / Raw(b"\x17" * payload) if payload else p

        syn_opts = [("MSS", 1460), ("NOP", None), ("WScale", 7), ("NOP", None), ("NOP", None), ("SAckOK", b"")]
        tr = self.trace
        tr.add(t, C("S", cseq, 0, opts=syn_opts))
        t1 = t + rtt
        tr.add(t1, S("SA", sseq, cseq + 1, opts=syn_opts))
        t2 = t1 + rng.uniform(0.0001, 0.0006)
        tr.add(t2, C("A", cseq + 1, sseq + 1))

        # Request, possibly lost upstream (after the mirror port) and retransmitted.
        tq = t2 + 0.0003
        tr.add(tq, C("PA", cseq + 1, sseq + 1, req))
        if rng.random() < up_loss:
            tq += max(0.2, 2 * rtt)
            tr.add(tq, C("PA", cseq + 1, sseq + 1, req))
        cnext = cseq + 1 + req

        # Response segments; downstream losses are never seen, only the hole they leave.
        segs = []
        snext = sseq + 1
        left = resp
        while left > 0:
            n = min(mss, left)
            segs.append((snext, n))
            snext += n
            left -= n
        seg_end = {seq: seq + n for seq, n in segs}
        received: set[int] = set()
        lost: list[tuple[int, int]] = []
        edge = sseq + 1

        def advance(e: int) -> int:
            while e in received:
                e = seg_end[e]
            return e

        ts = tq + rtt
        for i, (seq, n) in enumerate(segs):
            ts += rng.uniform(0.0002, 0.0012)
            if rng.random() < down_loss:
                lost.append((seq, n))
                if loss_side == "lan":
                    tr.add(ts, S("A", seq, cnext, n))  # the mirror saw it; the client never got it
                continue
            tr.add(ts, S("PA" if i == len(segs) - 1 else "A", seq, cnext, n))
            received.add(seq)
            edge = advance(edge)
            # ACK every second segment, and every segment once there is a hole (dup-ACKs).
            if lost or i % 2 == 1 or i == len(segs) - 1:
                tr.add(ts + 0.0001, C("A", cnext, edge))
        # Fast retransmit fills each hole roughly one RTT after the dup-ACKs.
        for seq, n in lost:
            ts += rtt + rng.uniform(0.001, 0.01)
            tr.add(ts, S("A", seq, cnext, n))
            received.add(seq)
            edge = advance(edge)
            tr.add(ts + 0.0001, C("A", cnext, edge))

        tc = ts + rng.uniform(0.05, 0.5)
        if close == "rst":
            tr.add(tc, C("RA", cnext, snext))
        else:
            tr.add(tc, C("FA", cnext, snext))
            tr.add(tc + rtt, S("FA", snext, cnext + 1))
            tr.add(tc + rtt + 0.0002, C("A", cnext + 1, snext + 1))
        return tc + rtt

    # --- DHCP -----------------------------------------------------------

    def dhcp_pkt(self, src_ip: str, src_mac: str, dst_ip: str, dst_mac: str, op: int, xid: int, chaddr: str,
                 options: list, yiaddr: str = "0.0.0.0", sport: int = 68, dport: int = 67):
        return (Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip, ttl=64 if op == 1 else 128)
                / UDP(sport=sport, dport=dport)
                / BOOTP(op=op, xid=xid, yiaddr=yiaddr, chaddr=bytes.fromhex(chaddr.replace(":", "")))
                / DHCP(options=options + ["end"]))

    def dhcp_discover(self, t: float, mac: str, xid: int, hostname: str = "laptop") -> None:
        self.trace.add(t, self.dhcp_pkt("0.0.0.0", mac, "255.255.255.255", BCAST, 1, xid, mac,
                                        [("message-type", "discover"), ("hostname", hostname.encode()),
                                         ("param_req_list", [1, 3, 6, 15, 51, 54])]))

    def dhcp_offer(self, t: float, server_ip: str, server_mac: str, mac: str, xid: int, yiaddr: str,
                   router: str, dns: list[str], mask: str = "255.255.255.0", kind: str = "offer") -> None:
        self.trace.add(t, self.dhcp_pkt(server_ip, server_mac, "255.255.255.255", BCAST, 2, xid, mac, [
            ("message-type", kind), ("server_id", server_ip), ("subnet_mask", mask), ("router", router),
            ("name_server", *dns), ("lease_time", 86400)], yiaddr=yiaddr, sport=67, dport=68))

    def dhcp_request(self, t: float, mac: str, xid: int, requested: str, server_ip: str) -> None:
        self.trace.add(t, self.dhcp_pkt("0.0.0.0", mac, "255.255.255.255", BCAST, 1, xid, mac, [
            ("message-type", "request"), ("requested_addr", requested), ("server_id", server_ip)]))

    def dhcp_dora(self, t: float, mac: str, yiaddr: str, server: Host | None = None,
                  router: str | None = None, dns: list[str] | None = None) -> float:
        server = server or self.gw
        xid = self.rng.getrandbits(32)
        router = router or self.gw.ip
        dns = dns or [self.resolver.ip]
        self.dhcp_discover(t, mac, xid)
        self.dhcp_offer(t + 0.004, server.ip, server.mac, mac, xid, yiaddr, router, dns)
        self.dhcp_request(t + 0.010, mac, xid, yiaddr, server.ip)
        self.dhcp_offer(t + 0.013, server.ip, server.mac, mac, xid, yiaddr, router, dns, kind="ack")
        return t + 0.013

    # --- background -----------------------------------------------------

    def mdns_announce(self, t: float, c: Host) -> None:
        pkt = (Ether(src=c.mac, dst="01:00:5e:00:00:fb") / IP(src=c.ip, dst="224.0.0.251", ttl=255)
               / UDP(sport=5353, dport=5353)
               / DNS(qr=0, qd=DNSQR(qname="_googlecast._tcp.local", qtype="PTR")))
        self.trace.add(t, pkt)

    def background(self, duration: float, intensity: float = 1.0, start: float = 0.0,
                   clients: list[Host] | None = None, sites: dict[str, str] | None = None,
                   rtt_for=None, loss_for=None, resolve=None) -> None:
        """Browsing-like traffic: DNS lookups followed by TCP sessions, plus some chatter.

        Hooks let a scenario bend the background: ``rtt_for(ip)`` and
        ``loss_for(client, ip) -> (down, up)`` change paths, and
        ``resolve(t, client, name) -> ip | None`` replaces the DNS step
        (None means the lookup failed and no session follows).
        """
        rng = self.rng
        clients = clients or self.clients
        sites = sites or SITES
        names = list(sites)
        for c in clients:
            t = start + rng.uniform(0.0, 3.0)
            while t < start + duration:
                name = rng.choice(names)
                if resolve:
                    t_ans, ip = resolve(t, c, name)
                else:
                    ip = sites[name]
                    t_ans = self.dns_lookup(t, c, name, answers=[ip])
                if ip:
                    for k in range(rng.choice([1, 1, 2, 3])):
                        rtt = rtt_for(ip) if rtt_for else None
                        down, up, *side = loss_for(c, ip) if loss_for else (0.0, 0.0)
                        close = "rst" if rng.random() < 0.15 else "fin"  # browsers often RST-close
                        self.tcp_session(t_ans + 0.001 + k * 0.01, c, ip, rng.choice([443, 443, 443, 80]),
                                         rtt=rtt, close=close, down_loss=down, up_loss=up,
                                         loss_side=side[0] if side else "wan")
                if rng.random() < 0.1:
                    self.mdns_announce(t + rng.uniform(0, 1), c)
                t += rng.expovariate(intensity / 4.0)
