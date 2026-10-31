"""DNS health and integrity.

Faults: resolvers that time out, return SERVFAIL or REFUSED, or answer slowly.
Attacks: forged answers, judged with the Hold-On test (Duan et al. 2012). We
learn each resolver's normal reply profile (IP TTL, round-trip time and, on a
LAN, source MAC) and flag replies that break it, above all when two replies to
one question disagree. A flood of replies matching no question is an off-path
poisoning attempt (Kaminsky / SAD DNS). See docs/research.md.
"""

from __future__ import annotations

import statistics
from collections import Counter, OrderedDict, defaultdict
from dataclasses import dataclass, field

from ..config import Limits
from ..decode.model import ACK, SYN, Packet
from ..evidence.describe import key_packet
from ..reasoning.differential import Differential, HypothesisDef, Observation, Rule
from ..reasoning.finding import Narrative, build_finding
from ..schema import Entity, Finding, KeyPacket, Verdict
from .arp import fmt_time
from .base import Context, Detector, is_private

TIMEOUT = 2.0
SINKHOLES = {"0.0.0.0", "127.0.0.1", "::", "::1"}  # noqa: S104 - answers we recognise, not addresses we bind
INTERNAL_SUFFIXES = (".local", ".lan", ".home", ".internal", ".corp", ".localdomain", ".home.arpa", ".intranet")


@dataclass(slots=True)
class Reply:
    ts: float
    frame: int
    mac: str | None
    ttl: int
    rcode: int
    answers: tuple
    kp: KeyPacket


@dataclass(slots=True)
class Txn:
    client: str
    server: str
    name: str
    ts: float
    frame: int
    retries: int = 0
    replies: list = field(default_factory=list)
    kp: KeyPacket | None = None


FAILURE = Differential(
    [
        HypothesisDef("failing", "DNS server failing", Verdict.FAULT, prior=-0.5),
        HypothesisDef("noise", "Occasional failed lookups", Verdict.BENIGN, prior=0.5),
        HypothesisDef("nonexistent", "Names that don't exist", Verdict.BENIGN, prior=0.0),
        HypothesisDef("capture", "Replies missing from the capture", Verdict.BENIGN, prior=-1.0),
    ],
    [
        Rule("failure_rate", "failing", 2.5, "{failed} of {total} lookups failed ({pct:.0%})"),
        Rule("failure_rate", "noise", -1.5, "Far more failures than normal background noise"),
        Rule("timeouts", "failing", 1.5, "{count} lookups got no answer at all, even after {retries} retries"),
        Rule("servfail", "failing", 1.5, "{count} lookups were answered with SERVFAIL ('server failure')"),
        Rule("refused", "failing", 1.5, "{count} lookups were answered with REFUSED"),
        Rule("many_clients", "failing", 1.0, "{count} different devices were affected"),
        Rule("many_clients", "noise", -1.0, "Several devices are affected"),
        Rule("onset", "failing", 1.0, "The server answered normally until {onset}, then started failing"),
        Rule("nxdomain_only", "nonexistent", 3.0, "The failures are 'no such name' answers ({count}), which a "
             "working server gives for typos, browser probes and search-suffix guesses"),
        Rule("nxdomain_only", "failing", -2.0, "The server answered every question; the names just don't exist"),
        Rule("silent_capture", "capture", 5.0, "Nothing at all was captured coming back from {server}"),
        Rule("silent_capture", "failing", -3.0, "The replies may exist but were not captured"),
    ],
)

FAILURE_TEXT = {
    "failing": Narrative(
        kind="dns_failure",
        title="DNS lookups are failing at {server}",
        simple=("{pct:.0%} of the name lookups sent to {server} {how} since {onset}. When lookups fail, websites "
                "and apps can't be found even though the network itself is up."),
        technical=("{failed} of {total} queries from {clients} client(s) failed ({breakdown}); first failure "
                   "{onset}; {retries} client retransmission(s)."),
        cause="{cause}",
        fix=("Restart the DNS server at {server} (often the router).",
             "Test with another resolver such as 1.1.1.1: if that works, the problem is {server}.",
             "{fix3}"),
    ),
    "noise": Narrative(
        kind="dns_failure_minor", title="A few DNS lookups failed at {server}",
        simple="A small number of lookups failed, which happens on every network.",
        technical="{failed} of {total} queries failed ({breakdown}).", cause="Transient failures.",
        fix=("Nothing to fix.",)),
    "nonexistent": Narrative(
        kind="dns_nxdomain", title="Lookups for names that don't exist",
        simple=("{count} lookups asked for names that don't exist. Browsers do this on purpose at startup, and "
                "typos do it too. The DNS server is working."),
        technical="{count} NXDOMAIN answers from {server}, no timeouts or server failures.",
        cause="Typos, browser hijack checks, and search-suffix guesses.", fix=("Nothing to fix.",)),
    "capture": Narrative(
        kind="capture_one_directional", title="DNS replies from {server} are missing from the capture",
        simple="Lookups look unanswered, but nothing at all was captured coming back from {server}, so the "
               "capture is probably one-directional.",
        technical="{failed} unanswered queries while {server} never transmits in the capture.",
        cause="Capture setup.", fix=("Capture both directions.",)),
}

SLOW = Differential(
    [
        HypothesisDef("slow", "Slow DNS", Verdict.FAULT, prior=-0.5),
        HypothesisDef("normal", "Normal DNS speed", Verdict.BENIGN, prior=0.5),
    ],
    [
        Rule("p95", "slow", 2.0, "The slowest 5% of lookups took over {p95_ms:.0f} ms"),
        Rule("median", "slow", 1.5, "A typical lookup took {p50_ms:.0f} ms (healthy is under 100 ms)"),
        Rule("many_slow", "slow", 1.0, "{pct:.0%} of lookups took longer than half a second"),
        Rule("onset", "slow", 0.5, "Lookups were fast until {onset}"),
    ],
)

SLOW_TEXT = {
    "slow": Narrative(
        kind="dns_slow",
        title="DNS at {server} is slow",
        simple=("Looking up a name takes about {p50_ms:.0f} ms, and up to {p95_ms:.0f} ms. Every new website waits "
                "that long before it even starts to load."),
        technical="Median {p50_ms:.0f} ms, p95 {p95_ms:.0f} ms over {samples} answered queries from {clients} "
                  "client(s).",
        cause="The DNS server is overloaded, or its upstream resolver or internet link is slow.",
        fix=("Restart the router or DNS server at {server}.",
             "Point devices (or the router's DHCP settings) at a faster resolver, then compare.",
             "Check whether the internet line is saturated."),
    ),
    "normal": Narrative(
        kind="dns_speed_ok", title="DNS speed at {server} is normal", simple="Lookups are reasonably fast.",
        technical="Median {p50_ms:.0f} ms.", cause="", fix=("Nothing to fix.",)),
}

SPOOF = Differential(
    [
        HypothesisDef("spoof", "Forged DNS answers", Verdict.ATTACK, prior=-2.0),
        HypothesisDef("path", "Answers relayed unchanged", Verdict.BENIGN, prior=0.0),
        HypothesisDef("blocking", "Deliberate ad/tracker blocking", Verdict.BENIGN, prior=-0.5),
        HypothesisDef("split", "Internal (split-horizon) names", Verdict.BENIGN, prior=-0.5),
    ],
    [
        Rule("conflict", "spoof", 3.5, "{count} question(s) got two different answers; the first one to arrive "
             "is the one the computer uses"),
        Rule("conflict", "path", -3.0, "A relay doesn't produce a second, different answer"),
        Rule("conflict", "blocking", -2.0, "A blocking DNS server answers once"),
        Rule("mac_mismatch", "spoof", 1.5, "{count} answer(s) came from MAC {mac}, not {usual} which delivers this "
             "DNS server's other answers"),
        Rule("ttl_mismatch", "spoof", 2.0, "{count} answer(s) arrived with IP TTL {ttl}; genuine answers from "
             "{server} arrive with {usual} (Hold-On test, +/-1 allowed)"),
        Rule("too_fast", "spoof", 1.5, "The suspect answers arrived in {rtt_ms:.1f} ms; {server} normally needs "
             "{usual_ms:.0f} ms, so they cannot have come from it"),
        Rule("too_fast", "path", -1.5, "Relaying adds delay, it doesn't remove it"),
        Rule("followed", "spoof", 0.8, "Victims then connected to the forged address {ips}"),
        Rule("answers_match", "path", 3.0, "The answers match what {server} gives everyone else, so they weren't "
             "altered"),
        Rule("answers_match", "spoof", -2.5, "The answers are the genuine ones"),
        Rule("sinkhole", "blocking", 3.5, "{count} answer(s) point to {addr}, which is how ad blockers like Pi-hole "
             "block a name"),
        Rule("sinkhole", "spoof", -1.5, "Pointing a name at nowhere protects users instead of redirecting them"),
        Rule("private_answer", "spoof", 1.0, "Public names ({names}) were pointed at a private address ({ips})"),
        Rule("internal_names", "split", 3.0, "The names are internal ({names}), which normally resolve to private "
             "addresses"),
        Rule("internal_names", "spoof", -1.0, "Internal names are expected to have internal addresses"),
    ],
)

SPOOF_TEXT = {
    "spoof": Narrative(
        kind="dns_spoofing",
        title="Forged DNS answers for {names}",
        simple=("Someone on your network answered {victims}'s DNS questions before the real DNS server could, "
                "pointing {names} to {forged}. Anyone visiting those sites may be sent to a fake copy that steals "
                "passwords."),
        technical=("{count} forged answer(s) for {names} from MAC {mac}, IP TTL {ttl} (genuine {usual_ttl}), "
                   "{rtt_ms:.1f} ms (genuine median {usual_ms:.0f} ms); {conflicts} transaction(s) had conflicting "
                   "answers. Judged with the Hold-On TTL and timing test."),
        cause="A DNS spoofing tool (dnsspoof, ettercap, bettercap) on the local network racing the real server.",
        fix=("Find and disconnect the device with MAC {mac}.",
             "On {victims}, clear the DNS cache (`ipconfig /flushdns`) and change any password typed into {names}.",
             "Turn on DNS-over-HTTPS in browsers, and use a resolver that validates DNSSEC."),
    ),
    "path": Narrative(
        kind="dns_relayed", title="DNS answers for {victims} passed through {mac}",
        simple=("DNS answers reached {victims} through another device ({mac}) but were not changed. On its own "
                "this is harmless; if an ARP spoofing finding names {mac}, it is part of that attack."),
        technical="{count} answers via {mac} instead of {usual}; answers identical to the resolver's.",
        cause="Traffic is being routed or relayed through {mac}.",
        fix=("If you don't recognise {mac}, check the ARP findings for this capture.",)),
    "blocking": Narrative(
        kind="dns_blocking", title="DNS is blocking some names",
        simple="The DNS server answers some names ({names}) with {forged}, which is how ad and tracker blocking "
               "works. This is deliberate.",
        technical="{count} sinkhole answers.", cause="An ad blocker such as Pi-hole or AdGuard.",
        fix=("Nothing to fix. If a site you need is blocked, allow it in the blocker.",)),
    "split": Narrative(
        kind="dns_split_horizon", title="Internal names resolve to private addresses",
        simple="Internal names ({names}) point at private addresses, which is normal.",
        technical="{count} answers.", cause="Split-horizon DNS.", fix=("Nothing to fix.",)),
}

POISON = Differential(
    [
        HypothesisDef("poison", "Off-path DNS poisoning attempt", Verdict.ATTACK, prior=-1.0),
        HypothesisDef("late", "Late answers to old questions", Verdict.BENIGN, prior=0.0),
    ],
    [
        Rule("burst", "poison", 4.0, "{count} answers 'from' {server} matched no question, {rate:.0f} per "
             "second, with {txids} different transaction IDs: brute-forcing the ID"),
        Rule("burst", "late", -3.0, "Late answers trickle in; they don't arrive in a burst"),
    ],
)

POISON_TEXT = {
    "poison": Narrative(
        kind="dns_poisoning_attempt",
        title="DNS cache poisoning attempt against {client}",
        simple=("{client} was flooded with {count} fake DNS answers pretending to come from {server}, each guessing "
                "a different transaction number. If one guess is right, the device will trust a forged address."),
        technical="{count} unmatched responses from {server} to {client} in {span:.1f} s, {txids} distinct TXIDs, "
                  "{ports} destination ports.",
        cause="A Kaminsky-style or SAD DNS-style off-path cache poisoning attack.",
        fix=("Find the source of the flood (frames below) and disconnect it.",
             "Make sure resolvers use source-port randomisation and DNSSEC validation.",
             "Flush the DNS cache on {client}."),
    ),
    "late": Narrative(
        kind="dns_late_answers", title="Unmatched DNS answers to {client}",
        simple="Some DNS answers arrived for questions not in the capture.", technical="{count} unmatched.",
        cause="Questions sent before the capture started.", fix=("Nothing to fix.",)),
}


def _internal(name: str) -> bool:
    return "." not in name.strip(".") or name.endswith(INTERNAL_SUFFIXES)


class DnsDetector(Detector):
    name = "dns"

    def __init__(self, limits: Limits):
        super().__init__(limits)
        self.txns: OrderedDict[tuple, Txn] = OrderedDict()
        self.done: list[Txn] = []
        self.queried: set[tuple[str, str]] = set()
        self.unmatched: dict[tuple[str, str], list[tuple[float, int, int, int]]] = defaultdict(list)
        self.syns: dict[tuple[str, str], float] = {}
        self.capped = False

    def on_packet(self, p: Packet) -> None:
        if p.tcp and p.tcp.flags & SYN and not p.tcp.flags & ACK and p.ip:
            k = (p.ip.src, p.ip.dst)
            if k not in self.syns and len(self.syns) < self.limits.max_flows:
                self.syns[k] = p.ts
            return
        d = p.dns
        if d is None or d.multicast or p.udp is None or p.ip is None or d.opcode != 0:
            return
        name = (d.qname or ".").lower()
        if not d.qr:
            key = (p.ip.src, p.udp.sport, p.ip.dst, d.id, name)
            t = self.txns.get(key)
            if t is not None:
                t.retries += 1
                return
            t = Txn(p.ip.src, p.ip.dst, name, p.ts, p.frame, kp=key_packet(p))
            self.txns[key] = t
            self.queried.add((p.ip.src, p.ip.dst))
            if len(self.txns) > self.limits.max_dns_transactions:
                self.capped = True
                self.done.append(self.txns.popitem(last=False)[1])
            return
        key = (p.ip.dst, p.udp.dport, p.ip.src, d.id, name)
        t = self.txns.get(key)
        if t is None:
            lst = self.unmatched[(p.ip.src, p.ip.dst)]
            if len(lst) < 5000:
                lst.append((p.ts, p.frame, d.id, p.udp.dport))
            return
        if len(t.replies) < 8:
            answers = tuple(sorted(a.data for a in d.answers if a.rtype in (1, 28)))
            t.replies.append(Reply(p.ts, p.frame, p.link.src if p.link else None, p.ip.ttl, d.rcode, answers,
                                   key_packet(p)))

    # --- end of capture -------------------------------------------------

    def finalize(self, ctx: Context) -> list[Finding]:
        if self.capped:
            ctx.counters.state_caps_hit.add("DNS transaction table")
        txns = self.done + list(self.txns.values())
        end = ctx.last_ts or 0.0
        by_server: dict[str, list[Txn]] = defaultdict(list)
        for t in txns:
            by_server[t.server].append(t)
        out: list[Finding] = []
        silent = ctx.silent_ips()
        for server, ts in by_server.items():
            base = self._baseline(ts)
            out += self._failures(server, ts, end, server in silent or ctx.gateway_silent() and not is_private(server))
            out += self._slow(server, ts)
            if base:
                out += self._integrity(server, ts, base)
        out += self._poisoning()
        return out

    @staticmethod
    def _baseline(ts: list[Txn]) -> dict | None:
        firsts = [t.replies[0] for t in ts if t.replies]
        if len(firsts) < 5:
            return None
        macs = Counter(r.mac for r in firsts)
        ttls = Counter(r.ttl for r in firsts)
        rtts = [t.replies[0].ts - t.ts for t in ts if t.replies]
        names: dict[str, set] = defaultdict(set)
        mac, _ = macs.most_common(1)[0]
        ttl, _ = ttls.most_common(1)[0]
        for t in ts:
            for r in t.replies:
                if r.mac == mac and abs(r.ttl - ttl) <= 1 and r.answers:
                    names[t.name].update(r.answers)
        return {"mac": mac, "mac_share": macs[mac] / len(firsts), "ttl": ttl,
                "rtt": statistics.median(rtts), "answers": names}

    def _failures(self, server: str, ts: list[Txn], end: float, silent: bool) -> list[Finding]:
        judged = [t for t in ts if t.replies or end - t.ts >= TIMEOUT]
        if len(judged) < 3:
            return []
        timeouts = [t for t in judged if not t.replies]
        servfail = [t for t in judged if t.replies and t.replies[0].rcode == 2]
        refused = [t for t in judged if t.replies and t.replies[0].rcode == 5]
        nx = [t for t in judged if t.replies and t.replies[0].rcode == 3]
        hard = timeouts + servfail + refused
        failed = hard + nx
        if len(failed) < 3:
            return []
        pct_hard = len(hard) / len(judged)
        obs = []
        if hard:
            obs.append(Observation("failure_rate", [t.frame for t in hard[:60]],
                                   {"failed": len(hard), "total": len(judged), "pct": pct_hard},
                                   strength=min(1.0, pct_hard / 0.3)))
        retries = sum(t.retries for t in timeouts)
        if timeouts:
            obs.append(Observation("timeouts", [t.frame for t in timeouts[:40]],
                                   {"count": len(timeouts), "retries": retries}, strength=min(1.0, len(timeouts) / 5)))
        if servfail:
            obs.append(Observation("servfail", [r.frame for t in servfail[:40] for r in t.replies[:1]],
                                   {"count": len(servfail)}, strength=min(1.0, len(servfail) / 5)))
        if refused:
            obs.append(Observation("refused", [r.frame for t in refused[:40] for r in t.replies[:1]],
                                   {"count": len(refused)}, strength=min(1.0, len(refused) / 5)))
        clients = {t.client for t in hard}
        if len(clients) >= 2:
            obs.append(Observation("many_clients", [], {"count": len(clients)}))
        onset = min((t.ts for t in hard), default=None)
        ok_before = [t for t in judged if t.replies and t.replies[0].rcode == 0 and onset and t.ts < onset]
        later_ok = [t for t in judged if t.replies and t.replies[0].rcode == 0 and onset and t.ts > onset]
        if hard and len(ok_before) >= 3 and len(later_ok) <= len(hard) / 3:
            obs.append(Observation("onset", [], {"onset": fmt_time(onset)}))
        if nx and len(hard) <= len(nx) / 10:
            obs.append(Observation("nxdomain_only", [t.frame for t in nx[:40]], {"count": len(nx)}))
        if silent:
            obs.append(Observation("silent_capture", [], {"server": server}))
        diagnosis = FAILURE.diagnose(obs, sufficient=len(hard) >= 3 or len(nx) >= 3)
        if diagnosis.verdict == Verdict.BENIGN and diagnosis.top == "noise":
            return []
        if timeouts and len(timeouts) >= max(len(servfail), len(refused)):
            how, cause = "got no answer at all", ("The DNS server has stopped or crashed, lost its own upstream "
                                                  "connection, or a firewall blocks port 53.")
            fix3 = "Check the router's internet connection and that its DNS service is enabled."
        elif servfail and len(servfail) >= len(refused):
            how, cause = "were answered with 'server failure'", ("The DNS server is running but can't reach the "
                                                                 "servers it forwards to (an upstream or DNSSEC "
                                                                 "problem).")
            fix3 = "Check the DNS server's upstream (forwarder) settings and its internet connection."
        else:
            how, cause = "were refused", ("The DNS server refuses to answer these devices: an access-control "
                                          "setting, or devices pointed at the wrong DNS server.")
            fix3 = "Check which DNS server the devices are configured with, and the server's allowed clients."
        breakdown = ", ".join(f"{n} {label}" for n, label in ((len(timeouts), "timeouts"),
                                                              (len(servfail), "SERVFAIL"),
                                                              (len(refused), "REFUSED"), (len(nx), "NXDOMAIN")) if n)
        start = onset if onset is not None else min(t.ts for t in failed)
        frames = [t.frame for t in hard] + [r.frame for t in hard for r in t.replies[:1]]
        return [build_finding(
            analyzer=self.name, diagnosis=diagnosis, narratives=FAILURE_TEXT,
            ctx={"server": server, "pct": pct_hard, "how": how, "onset": fmt_time(start), "failed": len(hard),
                 "total": len(judged), "clients": len({t.client for t in failed}), "breakdown": breakdown,
                 "retries": retries, "cause": cause, "fix3": fix3, "count": len(nx)},
            entities=[Entity(kind="ip", value=server, role="DNS server")]
            + [Entity(kind="ip", value=c, role="affected client") for c in sorted(clients)[:5]],
            frames=frames or [t.frame for t in nx], key_packets=[t.kp for t in (hard or nx)[:6] if t.kp]
            + [r.kp for t in (hard or nx)[:4] for r in t.replies[:1]],
            time_start=start, time_end=max(t.ts for t in failed),
            wireshark_filter=f"dns && ip.addr == {server}"
            + (" && dns.flags.rcode != 0" if not timeouts else ""),
            impact="critical_asset" if len(clients) >= 2 else "single_host",
            max_frames=self.limits.max_evidence_frames,
        )]

    def _slow(self, server: str, ts: list[Txn]) -> list[Finding]:
        answered = [t for t in ts if t.replies and t.replies[0].rcode in (0, 3)]
        if len(answered) < 5:
            return []
        rtts = sorted(t.replies[0].ts - t.ts for t in answered)
        p50 = statistics.median(rtts)
        p95 = rtts[int(0.95 * (len(rtts) - 1))]
        slow = [t for t in answered if t.replies[0].ts - t.ts > 0.5]
        if p95 < 0.5 and p50 < 0.3:
            return []
        obs = []
        if p95 >= 0.5:
            obs.append(Observation("p95", [], {"p95_ms": p95 * 1000}, strength=min(1.0, p95 / 1.0)))
        if p50 >= 0.3:
            obs.append(Observation("median", [], {"p50_ms": p50 * 1000}, strength=min(1.0, p50 / 0.6)))
        if len(slow) / len(answered) >= 0.25:
            obs.append(Observation("many_slow", [t.frame for t in slow[:40]], {"pct": len(slow) / len(answered)}))
        first_slow = min((t.ts for t in slow), default=None)
        if first_slow and sum(1 for t in answered if t.ts < first_slow) >= 3:
            obs.append(Observation("onset", [], {"onset": fmt_time(first_slow)}))
        diagnosis = SLOW.diagnose(obs, sufficient=len(slow) >= 3)
        if diagnosis.verdict == Verdict.BENIGN:
            return []
        return [build_finding(
            analyzer=self.name, diagnosis=diagnosis, narratives=SLOW_TEXT,
            ctx={"server": server, "p50_ms": p50 * 1000, "p95_ms": p95 * 1000, "samples": len(answered),
                 "clients": len({t.client for t in answered})},
            entities=[Entity(kind="ip", value=server, role="DNS server")],
            frames=[f for t in slow for f in (t.frame, t.replies[0].frame)],
            key_packets=[k for t in slow[:3] for k in (t.kp, t.replies[0].kp) if k],
            time_start=min((t.ts for t in slow), default=answered[0].ts),
            time_end=max((t.ts for t in slow), default=answered[-1].ts),
            wireshark_filter=f"dns.time > 0.5 && ip.src == {server}",
            impact="multi_host", max_frames=self.limits.max_evidence_frames,
        )]

    def _integrity(self, server: str, ts: list[Txn], base: dict) -> list[Finding]:
        """Sort replies that break the resolver's profile into forged and merely relayed ones.

        A man-in-the-middle relays genuine answers through its own MAC (with the TTL one
        lower) as well as forging some. Only the forged ones are spoofing evidence; the
        relayed ones are reported separately as a harmless path change.
        """
        groups: dict[tuple[str, str], list[tuple[Txn, Reply, bool]]] = defaultdict(list)
        sinkholes: list[tuple[Txn, Reply]] = []
        genuine = base["answers"]
        for t in ts:
            answered = [r for r in t.replies if r.rcode == 0]
            conflict = len({r.answers for r in answered}) > 1
            known = genuine.get(t.name, set())
            first_answer = min(answered, key=lambda r: r.ts) if answered else None
            for r in t.replies:
                if r.answers and set(r.answers) <= SINKHOLES:
                    sinkholes.append((t, r))
                    continue
                odd_mac = base["mac_share"] >= 0.8 and r.mac != base["mac"]
                odd_ttl = abs(r.ttl - base["ttl"]) > 1
                too_fast = base["rtt"] >= 0.002 and (r.ts - t.ts) < 0.5 * base["rtt"]
                matches = bool(r.answers) and set(r.answers) <= known
                if conflict:
                    # The genuine answer is the one the resolver gives everyone; failing that,
                    # the forger is the one that raced in first.
                    forged = not matches if known else r is first_answer
                else:
                    # Timing alone only decides between competing replies (Hold-On); a lone quick
                    # reply is normal. A lone reply is forged only if it breaks the profile and
                    # also gives an answer the resolver doesn't give anyone else.
                    forged = not matches and (odd_ttl or (odd_mac and too_fast))
                if forged:
                    groups[("forged", r.mac or f"ttl {r.ttl}")].append((t, r, conflict))
                elif odd_mac or odd_ttl:
                    groups[("relayed", r.mac or f"ttl {r.ttl}")].append((t, r, False))
        out = []
        for (_kind, mac), items in groups.items():
            out.append(self._spoof_finding(server, base, mac, items))
        if len(sinkholes) >= 3:
            names = sorted({t.name for t, _ in sinkholes})
            addr = sorted({a for _, r in sinkholes for a in r.answers})[0]
            diagnosis = SPOOF.diagnose([Observation("sinkhole", [r.frame for _, r in sinkholes[:40]],
                                                    {"count": len(sinkholes), "addr": addr})])
            out.append(build_finding(
                analyzer=self.name, diagnosis=diagnosis, narratives=SPOOF_TEXT,
                ctx={"names": ", ".join(names[:4]), "forged": addr, "count": len(sinkholes), "victims": "",
                     "mac": base["mac"], "usual": base["mac"]},
                entities=[Entity(kind="ip", value=server, role="DNS server")]
                + [Entity(kind="domain", value=n) for n in names[:5]],
                frames=[r.frame for _, r in sinkholes], key_packets=[r.kp for _, r in sinkholes[:5]],
                time_start=sinkholes[0][1].ts, time_end=sinkholes[-1][1].ts,
                wireshark_filter=f"dns.a == {addr}" if ":" not in addr else f"dns.aaaa == {addr}",
                impact="minor", max_frames=self.limits.max_evidence_frames,
            ))
        return out

    def _spoof_finding(self, server: str, base: dict, mac: str, items: list[tuple[Txn, Reply, bool]]) -> Finding:
        conflicts = {id(t) for t, _, c in items if c}
        names = sorted({t.name for t, _, _ in items})
        forged = sorted({a for _, r, _ in items for a in r.answers})
        victims = sorted({t.client for t, _, _ in items})
        ttls = Counter(r.ttl for _, r, _ in items)
        rtts = [r.ts - t.ts for t, r, _ in items]
        obs = []
        frames = [r.frame for _, r, _ in items] + [t.frame for t, _, _ in items]
        if conflicts:
            obs.append(Observation("conflict", frames[:60], {"count": len(conflicts)},
                                   strength=min(1.0, len(conflicts) / 2)))
        mac_hits = [r for _, r, _ in items if r.mac != base["mac"]]
        if mac_hits and base["mac_share"] >= 0.8:
            obs.append(Observation("mac_mismatch", [r.frame for r in mac_hits[:40]],
                                   {"count": len(mac_hits), "mac": mac, "usual": base["mac"]}))
        ttl, _ = ttls.most_common(1)[0]
        if abs(ttl - base["ttl"]) > 1:
            obs.append(Observation("ttl_mismatch", [], {"count": ttls[ttl], "ttl": ttl, "usual": base["ttl"],
                                                        "server": server}))
        median_rtt = statistics.median(rtts)
        if base["rtt"] >= 0.002 and median_rtt < 0.5 * base["rtt"]:
            obs.append(Observation("too_fast", [], {"rtt_ms": median_rtt * 1000, "usual_ms": base["rtt"] * 1000,
                                                    "server": server}))
        followed = sorted({ip for t, r, _ in items for ip in r.answers
                           if (t.client, ip) in self.syns and self.syns[(t.client, ip)] >= r.ts})
        if followed:
            obs.append(Observation("followed", [], {"ips": ", ".join(followed[:3])}))
        genuine = base["answers"]
        consistent = [r for t, r, _ in items if r.answers and set(r.answers) <= genuine.get(t.name, set())]
        if consistent and len(consistent) >= 0.8 * len(items) and not conflicts:
            obs.append(Observation("answers_match", [], {"server": server}))
        public_names = [n for n in names if not _internal(n)]
        private = [a for a in forged if is_private(a)]
        if private and public_names:
            obs.append(Observation("private_answer", [], {"names": ", ".join(public_names[:3]),
                                                          "ips": ", ".join(private[:3])}))
        if names and all(_internal(n) for n in names):
            obs.append(Observation("internal_names", [], {"names": ", ".join(names[:3])}))
        diagnosis = SPOOF.diagnose(obs, sufficient=bool(conflicts) or len(items) >= 2)
        kp = [k for t, r, _ in items[:4] for k in [t.kp] + [x.kp for x in t.replies] if k]
        return build_finding(
            analyzer=self.name, diagnosis=diagnosis, narratives=SPOOF_TEXT,
            ctx={"names": ", ".join(names[:4]), "forged": ", ".join(forged[:3]) or "other addresses",
                 "victims": ", ".join(victims[:3]), "count": len(items), "mac": mac, "usual": base["mac"],
                 "ttl": ttl, "usual_ttl": base["ttl"], "rtt_ms": median_rtt * 1000, "usual_ms": base["rtt"] * 1000,
                 "conflicts": len(conflicts)},
            entities=[Entity(kind="domain", value=n, role="spoofed name") for n in names[:6]]
            + [Entity(kind="mac", value=mac, role="forger")]
            + [Entity(kind="ip", value=a, role="forged answer") for a in forged[:3]]
            + [Entity(kind="ip", value=v, role="victim") for v in victims[:3]]
            + [Entity(kind="ip", value=server, role="DNS server")],
            frames=frames, key_packets=kp, time_start=min(r.ts for _, r, _ in items),
            time_end=max(r.ts for _, r, _ in items),
            wireshark_filter=f"dns.flags.response == 1 && eth.src == {mac}" if ":" in mac
            else f"dns.flags.response == 1 && ip.src == {server}",
            impact="critical_asset" if conflicts else "single_host",
            max_frames=self.limits.max_evidence_frames,
        )

    def _poisoning(self) -> list[Finding]:
        out = []
        for (server, client), lst in self.unmatched.items():
            if (client, server) not in self.queried or len(lst) < 20:
                continue
            lst.sort()
            best, i = (0, 0, 0), 0
            for j in range(len(lst)):
                while lst[j][0] - lst[i][0] > 10.0:
                    i += 1
                if j - i + 1 > best[0]:
                    best = (j - i + 1, i, j)
            n, i, j = best
            if n < 20:
                continue
            window = lst[i:j + 1]
            span = max(window[-1][0] - window[0][0], 0.001)
            txids = len({w[2] for w in window})
            diagnosis = POISON.diagnose([Observation("burst", [w[1] for w in window[:100]],
                                                     {"count": n, "server": server, "rate": n / span,
                                                      "txids": txids})])
            out.append(build_finding(
                analyzer=self.name, diagnosis=diagnosis, narratives=POISON_TEXT,
                ctx={"client": client, "server": server, "count": n, "span": span, "txids": txids,
                     "ports": len({w[3] for w in window})},
                entities=[Entity(kind="ip", value=client, role="target"),
                          Entity(kind="ip", value=server, role="impersonated DNS server")],
                frames=[w[1] for w in window], key_packets=[], time_start=window[0][0], time_end=window[-1][0],
                wireshark_filter=f"dns.flags.response == 1 && ip.src == {server} && ip.dst == {client}",
                impact="single_host", max_frames=self.limits.max_evidence_frames,
            ))
        return out
