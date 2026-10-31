"""TCP health: loss, refused and unanswered connections, slow servers.

Out-of-sequence segments are classified the way Jaiswal et al. do from a
mid-path vantage point (docs/research.md):

- a segment seen twice is a retransmission: it was lost *after* the capture point;
- a hole filled more than half an RTT later is a retransmission of a segment lost
  *before* the capture point;
- a hole filled sooner is reordering, not loss;
- a copy of data the receiver had already acknowledged is a spurious retransmission;
- data acknowledged but never seen is a capture gap: our capture missed it, the
  network did not.

Loss is then localised Sherlock-style: which single component (one server, one
client's link, or everything through the gateway) explains the lossy flows.
"""

from __future__ import annotations

import statistics
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field

from ..config import Limits
from ..decode.model import ACK, FIN, RST, SYN, Packet
from ..evidence.describe import key_packet
from ..reasoning.differential import Differential, HypothesisDef, Observation, Rule
from ..reasoning.finding import Narrative, build_finding
from ..schema import Entity, Finding, Verdict
from .arp import fmt_time
from .base import Context, Detector, is_private

MASK = 0xFFFFFFFF
UNANSWERED_AFTER = 3.0


def sdiff(a: int, b: int) -> int:
    """a - b in 32-bit sequence space."""
    d = (a - b) & MASK
    return d - 0x100000000 if d & 0x80000000 else d


@dataclass(slots=True)
class Dir:
    hi: int | None = None
    acked: int | None = None
    seen: dict = field(default_factory=dict)       # seq -> (ts, len, frame)
    holes: list = field(default_factory=list)      # [start, end, ts_opened]
    data: int = 0
    retrans: int = 0
    late_fill: int = 0
    reorder: int = 0
    spurious: int = 0
    acked_unseen: int = 0
    loss_frames: list = field(default_factory=list)


@dataclass(slots=True)
class Flow:
    client: str
    cport: int
    server: str
    sport: int
    first_ts: float
    last_ts: float
    syn_ts: float | None = None
    syn_seq: int | None = None
    syn_retx: int = 0
    syn_frames: list = field(default_factory=list)
    synack_ts: float | None = None
    rtt: float | None = None
    refused_frame: int | None = None
    c2s: Dir = field(default_factory=Dir)
    s2c: Dir = field(default_factory=Dir)
    kp: list = field(default_factory=list)


@dataclass
class PairStats:
    flows: int = 0
    data: int = 0
    loss: int = 0
    wan: int = 0
    lan: int = 0
    reorder: int = 0
    spurious: int = 0
    acked_unseen: int = 0
    frames: list = field(default_factory=list)
    kp: list = field(default_factory=list)
    first_ts: float = 0.0
    last_ts: float = 0.0


LOSS = Differential(
    [
        HypothesisDef("loss", "Packet loss", Verdict.FAULT, prior=0.0),
        HypothesisDef("reorder", "Reordering, not loss", Verdict.BENIGN, prior=-0.5),
        HypothesisDef("capture", "Capture missed packets", Verdict.BENIGN, prior=-0.5),
        HypothesisDef("normal", "Normal background loss", Verdict.BENIGN, prior=0.5),
    ],
    [
        Rule("loss_rate", "loss", 2.5, "{rate:.1%} of data segments had to be resent ({events} of {segments})"),
        Rule("loss_rate", "normal", -1.5, "Far above the fraction of a percent that healthy links lose"),
        Rule("localised", "loss", 1.5, "{scope}"),
        Rule("localised", "normal", -1.0, "Loss concentrates on one component instead of being spread thinly"),
        Rule("others_clean", "loss", 1.0, "Other traffic in the capture is fine ({other_rate:.1%} loss)"),
        Rule("many_flows", "loss", 0.8, "{flows} of {total_flows} connection(s) were affected"),
        Rule("mostly_reordering", "reorder", 3.0, "{count} segments arrived out of order but were not lost"),
        Rule("mostly_reordering", "loss", -1.0, "Many 'missing' segments turned up moments later"),
        Rule("capture_gaps", "capture", 3.0, "{count} segments were acknowledged by the receiver but never captured"),
        Rule("capture_gaps", "loss", -1.0, "Some apparent gaps are the capture's, not the network's"),
        Rule("spurious", "normal", 1.0, "{count} resends were of data already acknowledged (an impatient timer)"),
    ],
)

LOSS_TEXT = {
    "loss": Narrative(
        kind="tcp_retransmissions",
        title="Packet loss {where_short}",
        simple=("{rate:.0%} of the data {subject} had to be sent again because it got lost{where_long}. Users "
                "see this as slow pages, stalled downloads and choppy calls."),
        technical=("{events} retransmissions over {segments} data segments ({rate:.1%}) in {flows} connection(s); "
                   "{wan} lost beyond the capture point towards the far side, {lan} on the local side. "
                   "Classified per segment: retransmission vs. late hole fill vs. reordering vs. capture gap."),
        cause="{cause}",
        fix=("{fix1}", "{fix2}", "{fix3}"),
    ),
    "reorder": Narrative(
        kind="tcp_reordering", title="Packets arriving out of order {where_short}",
        simple="Packets {subject} often arrive out of order, but they are not lost. This is usually harmless.",
        technical="{reorder} reordered segments, {events} real retransmissions.",
        cause="Multiple network paths or load balancing.", fix=("Nothing to fix unless users report problems.",)),
    "capture": Narrative(
        kind="capture_gaps", title="The capture missed packets {where_short}",
        simple="Some packets were acknowledged by the receiver but never appear in the capture: the capture dropped "
               "them, not the network.",
        technical="{acked_unseen} acknowledged-but-unseen segments.",
        cause="The capturing machine or mirror port could not keep up.",
        fix=("Capture with a larger buffer, or on a less busy port.",)),
    "normal": Narrative(
        kind="tcp_retransmissions_normal", title="Normal, low packet loss {where_short}",
        simple="A few packets were resent, which every healthy network does occasionally.",
        technical="{events} retransmissions over {segments} data segments ({rate:.1%}).",
        cause="Ordinary congestion.", fix=("Nothing to fix.",)),
}

REFUSED = Differential(
    [
        HypothesisDef("down", "Service stopped or not listening", Verdict.FAULT, prior=0.0),
        HypothesisDef("one_off", "A single closed port", Verdict.BENIGN, prior=0.5),
    ],
    [
        Rule("attempts", "down", 1.5, "{count} connection attempts to port {port} were refused"),
        Rule("clients", "down", 1.5, "{count} different devices were refused"),
        Rule("clients", "one_off", -1.0, "Several devices depend on this service"),
        Rule("retries", "down", 0.5, "Devices kept retrying"),
        Rule("was_up", "down", 1.0, "The same service accepted connections earlier in the capture"),
    ],
)

REFUSED_TEXT = {
    "down": Narrative(
        kind="connection_refused",
        title="{server} is refusing connections on port {port}",
        simple=("Devices tried {count} times to connect to {server} on port {port} ({service}), and every attempt "
                "was turned away straight away. The machine is on, but the program behind that port isn't running."),
        technical="{count} SYNs answered with RST/ACK from {server}:{port} by {clients} client(s), {first}-{last}.",
        cause="The service crashed or was stopped, is listening on a different port, or a local firewall rejects it.",
        fix=("On {server}, check that the service on port {port} is running and restart it.",
             "Confirm it listens on port {port} (e.g. `netstat -an` or `ss -ltn`).",
             "If a firewall on {server} was changed recently, allow port {port} again."),
    ),
    "one_off": Narrative(
        kind="connection_refused_once", title="A connection to {server}:{port} was refused",
        simple="One device tried a port that isn't open. That happens and is harmless on its own.",
        technical="{count} refused SYN(s).", cause="A closed port.", fix=("Nothing to fix.",)),
}

UNANSWERED = Differential(
    [
        HypothesisDef("down", "Host or service unreachable", Verdict.FAULT, prior=0.0),
        HypothesisDef("capture", "Replies missing from the capture", Verdict.BENIGN, prior=-1.0),
        HypothesisDef("one_off", "A single failed attempt", Verdict.BENIGN, prior=0.5),
    ],
    [
        Rule("attempts", "down", 1.5, "{count} connection attempt(s) to {server} got no answer at all"),
        Rule("backoff", "down", 1.0, "Devices retried with growing delays ({retx} retries), the normal TCP give-up "
             "pattern"),
        Rule("clients", "down", 1.5, "{count} different devices could not reach it"),
        Rule("clients", "one_off", -1.0, "More than one device is affected"),
        Rule("resolved", "down", 1.0, "Its address came from DNS, so people really were trying to use it"),
        Rule("others_fine", "down", 0.8, "Connections to other servers worked at the same time"),
        Rule("silent_capture", "capture", 4.0, "Nothing at all was captured from that direction, so replies may "
             "simply be missing from the capture"),
        Rule("silent_capture", "down", -3.0, "The capture is one-directional here"),
    ],
)

UNANSWERED_TEXT = {
    "down": Narrative(
        kind="host_unreachable",
        title="{server} is not answering connections",
        simple=("{clients} device(s) tried to connect to {server} (port {ports}) and never got a reply, not even a "
                "refusal. It is switched off, unreachable from here, or a firewall is silently dropping the traffic."),
        technical=("{count} SYN-only connection attempt(s) with {retx} retransmission(s), no SYN/ACK, RST or ICMP "
                   "between {first} and {last}."),
        cause="The server is down, the route to it is broken, or a firewall drops the packets.",
        fix=("Check whether {server} is up from another network (for example a phone on mobile data).",
             "If it is a service you run, check its server and its firewall rules for port {ports}.",
             "If only this office is affected, check the router's firewall and routes."),
    ),
    "capture": Narrative(
        kind="capture_one_directional", title="Replies from {server} are missing from the capture",
        simple="Connections to {server} look unanswered, but nothing at all was captured coming back, so the "
               "capture is probably one-directional.",
        technical="Unanswered SYNs while the reverse direction is silent.", cause="Capture setup.",
        fix=("Capture both directions.",)),
    "one_off": Narrative(
        kind="host_unreachable_once", title="One connection to {server} went unanswered",
        simple="A single connection attempt got no reply. On its own that is not a problem.",
        technical="{count} unanswered SYN(s).", cause="A transient failure.", fix=("Nothing to fix.",)),
}

OUTAGE = Differential(
    [
        HypothesisDef("uplink", "Internet connection down", Verdict.FAULT, prior=0.0),
        HypothesisDef("capture", "Replies missing from the capture", Verdict.BENIGN, prior=-1.0),
    ],
    [
        Rule("many_servers", "uplink", 2.0, "{count} different internet servers stopped answering at the same time"),
        Rule("many_clients", "uplink", 1.5, "{count} different devices were affected"),
        Rule("worked_before", "uplink", 1.5, "Internet connections worked until {onset}"),
        Rule("silent_capture", "capture", 5.0, "Nothing at all was captured coming back through the gateway"),
        Rule("silent_capture", "uplink", -3.0, "The replies may exist but were not captured"),
    ],
)

OUTAGE_TEXT = {
    "uplink": Narrative(
        kind="connectivity_outage",
        title="The internet connection appears to be down",
        simple=("From {onset}, {clients} devices could not reach {count} different internet servers that were "
                "working before. Nothing came back at all, which points to the router or the internet line, not "
                "to the individual websites."),
        technical=("{attempts} unanswered connection attempts ({retx} retransmissions) to {count} public servers "
                   "from {clients} clients after {onset}; {ok_before} connections succeeded before."),
        cause="The internet line, the modem or the router's WAN side is down, or a firewall started dropping traffic.",
        fix=("Check the router's and modem's internet/WAN lights, then restart the modem and router.",
             "Plug a laptop straight into the modem to see whether the line itself works.",
             "If it is the line, contact your internet provider with the time it started ({onset})."),
    ),
    "capture": Narrative(
        kind="capture_one_directional", title="Replies from the internet are missing from the capture",
        simple="Connections to many internet servers look unanswered, but nothing at all was captured coming "
               "back through the gateway, so the capture is probably one-directional.",
        technical="{attempts} unanswered attempts.", cause="Capture setup.", fix=("Capture both directions.",)),
}

LATENCY = Differential(
    [
        HypothesisDef("slow", "Unusually slow path or server", Verdict.FAULT, prior=-0.5),
        HypothesisDef("far", "Far-away server, normal for its distance", Verdict.BENIGN, prior=0.5),
    ],
    [
        Rule("absolute", "slow", 2.0, "Connections take {median_ms:.0f} ms just to start (median of {samples})"),
        Rule("relative", "slow", 1.5, "{ratio:.0f}x slower than the other servers here (median {base_ms:.0f} ms)"),
        Rule("relative", "far", -0.5, "Much slower than other servers in the same capture"),
        Rule("jitter", "slow", 0.8, "Delay varies widely ({spread_ms:.0f} ms spread), a sign of congestion"),
        Rule("steady", "far", 1.0, "Delay is steady, as distance would make it"),
    ],
)

LATENCY_TEXT = {
    "slow": Narrative(
        kind="high_latency",
        title="{server} is very slow to respond",
        simple=("Every connection to {server} waits about {median_ms:.0f} ms before anything happens, about "
                "{ratio:.0f} times longer than other servers. Pages from it will feel sluggish."),
        technical=("Handshake RTT to {server}: median {median_ms:.0f} ms, p90 {p90_ms:.0f} ms over {samples} "
                   "connections; other servers median {base_ms:.0f} ms."),
        cause="Congestion on the path to that server, an overloaded server, or a very long route.",
        fix=("Check whether the delay is the same from another network; if so the problem is on the server's side.",
             "If only this office is slow to it, look for a saturated uplink (large uploads or backups).",
             "Contact the service provider with these timings if it persists."),
    ),
    "far": Narrative(
        kind="high_latency_distance", title="{server} is far away",
        simple="Connections to {server} are slower than others but steady, which fits a distant server.",
        technical="Median handshake RTT {median_ms:.0f} ms.", cause="Distance.", fix=("Nothing to fix.",)),
}

SERVICE_NAMES = {21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
                 445: "file sharing (SMB)", 993: "IMAPS", 1433: "SQL Server", 3306: "MySQL", 3389: "Remote Desktop",
                 5432: "PostgreSQL", 8080: "web application", 8443: "web application (HTTPS)"}


class TcpHealthDetector(Detector):
    name = "tcp"

    def __init__(self, limits: Limits):
        super().__init__(limits)
        self.flows: OrderedDict[tuple, Flow] = OrderedDict()
        self.pairs: dict[tuple[str, str], PairStats] = defaultdict(PairStats)
        self.refused: dict[tuple[str, int], list[tuple[str, float, int, int]]] = defaultdict(list)
        self.unanswered: dict[str, list[tuple[str, float, list[int], int, int]]] = defaultdict(list)
        self.ok_service: dict[tuple[str, int], float] = {}
        self.rtt: dict[str, list[float]] = defaultdict(list)
        self.capped = False

    # --- per packet -----------------------------------------------------

    def on_packet(self, p: Packet) -> None:
        t, ip = p.tcp, p.ip
        if t is None or ip is None:
            return
        a, b = (ip.src, t.sport), (ip.dst, t.dport)
        key = (a, b) if a <= b else (b, a)
        fl = self.flows.get(key)
        syn, ack, rst, fin = t.flags & SYN, t.flags & ACK, t.flags & RST, t.flags & FIN
        if fl is not None and syn and not ack and ip.src == fl.client and fl.syn_seq is not None \
                and t.seq != fl.syn_seq and fl.synack_ts is not None:
            self._retire(self.flows.pop(key), p.ts)  # port reused for a new connection
            fl = None
        if fl is None:
            if syn and not ack:
                client, cport, server, sport = ip.src, t.sport, ip.dst, t.dport
            elif syn and ack:
                client, cport, server, sport = ip.dst, t.dport, ip.src, t.sport
            elif t.sport > t.dport:
                client, cport, server, sport = ip.src, t.sport, ip.dst, t.dport
            else:
                client, cport, server, sport = ip.dst, t.dport, ip.src, t.sport
            fl = Flow(client, cport, server, sport, p.ts, p.ts)
            self.flows[key] = fl
            if len(self.flows) > self.limits.max_flows:
                self.capped = True
                _, old = self.flows.popitem(last=False)
                self._retire(old, p.ts)
        else:
            self.flows.move_to_end(key)
        fl.last_ts = p.ts
        c2s = ip.src == fl.client and t.sport == fl.cport
        d, peer = (fl.c2s, fl.s2c) if c2s else (fl.s2c, fl.c2s)
        if len(fl.kp) < 6 and (syn or rst):
            fl.kp.append(key_packet(p))

        if syn and not ack:
            if c2s:
                if fl.syn_ts is None:
                    fl.syn_ts, fl.syn_seq = p.ts, t.seq
                elif t.seq == fl.syn_seq:
                    fl.syn_retx += 1
                if len(fl.syn_frames) < 10:
                    fl.syn_frames.append(p.frame)
                d.hi = (t.seq + 1) & MASK
            return
        if syn and ack:
            if not c2s and fl.synack_ts is None:
                fl.synack_ts = p.ts
                if fl.syn_ts is not None and fl.syn_retx == 0:
                    fl.rtt = p.ts - fl.syn_ts  # Karn: no RTT sample from a retransmitted SYN
            d.hi = (t.seq + 1) & MASK
            return
        if rst:
            if not c2s and fl.synack_ts is None and fl.syn_ts is not None and fl.refused_frame is None:
                fl.refused_frame = p.frame
            return
        if ack:
            self._ack(peer, t.ack)
        length = t.payload_len + (1 if fin else 0)
        if length:
            self._data(fl, d, peer, t.seq, length, t.payload_len, p)

    @staticmethod
    def _ack(peer: Dir, ackno: int) -> None:
        if peer.acked is None or sdiff(ackno, peer.acked) > 0:
            peer.acked = ackno
        if peer.hi is not None and sdiff(ackno, peer.hi) > 0:
            peer.acked_unseen += 1  # the receiver has data we never saw
            peer.hi = ackno
        if peer.holes:
            kept = []
            for h in peer.holes:
                if sdiff(ackno, h[1]) >= 0:
                    peer.acked_unseen += 1  # acknowledged hole never filled in our capture
                else:
                    kept.append(h)
            peer.holes = kept

    def _data(self, fl: Flow, d: Dir, peer: Dir, seq: int, length: int, payload: int, p: Packet) -> None:
        end = (seq + length) & MASK
        if payload:
            d.data += 1
        if d.hi is None:
            d.hi = end
        else:
            diff = sdiff(seq, d.hi)
            if diff > 0:
                if len(d.holes) < 64:
                    d.holes.append([d.hi, seq, p.ts])
                d.hi = end
            elif diff < 0:
                if payload <= 1 and sdiff(end, d.hi) <= 0 and sdiff(seq, d.hi) == -1:
                    return  # keep-alive probe
                hole = next((h for h in d.holes if sdiff(seq, h[0]) >= 0 and sdiff(seq, h[1]) < 0), None)
                prev = d.seen.get(seq)
                if hole is not None:
                    rtt = fl.rtt if fl.rtt else 0.05
                    if p.ts - hole[2] < max(0.003, 0.5 * rtt):
                        d.reorder += 1
                    else:
                        d.late_fill += 1
                        if len(d.loss_frames) < 40:
                            d.loss_frames.append(p.frame)
                    if sdiff(end, hole[1]) >= 0 and seq == hole[0]:
                        d.holes.remove(hole)
                    elif seq == hole[0]:
                        hole[0] = end
                elif prev is not None:
                    if d.acked is not None and sdiff(d.acked, end) >= 0:
                        d.spurious += 1
                    elif p.ts - prev[0] < 0.003 and prev[1] == length:
                        pass  # duplicated by the network or the capture setup; not loss
                    else:
                        d.retrans += 1
                        if len(d.loss_frames) < 40:
                            d.loss_frames.append(p.frame)
                if sdiff(end, d.hi) > 0:
                    d.hi = end
            else:
                d.hi = end
        d.seen[seq] = (p.ts, length, p.frame)
        if len(d.seen) > 256:
            del d.seen[next(iter(d.seen))]

    def _retire(self, fl: Flow, now: float) -> None:
        if fl.synack_ts is not None:
            self.ok_service.setdefault((fl.server, fl.sport), fl.synack_ts)
            if fl.rtt is not None and len(self.rtt[fl.server]) < 500:
                self.rtt[fl.server].append(fl.rtt)
        elif fl.refused_frame is not None:
            self.refused[(fl.server, fl.sport)].append((fl.client, fl.syn_ts or fl.first_ts, fl.refused_frame,
                                                        fl.syn_retx))
        elif fl.syn_ts is not None and now - fl.syn_ts >= UNANSWERED_AFTER:
            self.unanswered[fl.server].append((fl.client, fl.syn_ts, fl.syn_frames, fl.syn_retx, fl.sport))
        c, s = fl.c2s, fl.s2c
        data = c.data + s.data
        if not data:
            return
        ps = self.pairs[(fl.client, fl.server)]
        if not ps.flows:
            ps.first_ts = fl.first_ts
        ps.flows += 1
        ps.last_ts = max(ps.last_ts, fl.last_ts)
        ps.data += data
        ps.wan += c.retrans + s.late_fill
        ps.lan += c.late_fill + s.retrans
        ps.loss += c.retrans + s.late_fill + c.late_fill + s.retrans
        ps.reorder += c.reorder + s.reorder
        ps.spurious += c.spurious + s.spurious
        ps.acked_unseen += c.acked_unseen + s.acked_unseen
        if len(ps.frames) < 200:
            ps.frames += (c.loss_frames + s.loss_frames)[:20]
        if (c.retrans or s.retrans or c.late_fill or s.late_fill) and len(ps.kp) < 4:
            ps.kp += fl.kp[:2]

    # --- end of capture -------------------------------------------------

    def finalize(self, ctx: Context) -> list[Finding]:
        now = ctx.last_ts or 0.0
        for fl in list(self.flows.values()):
            self._retire(fl, now)
        self.flows.clear()
        if self.capped:
            ctx.counters.state_caps_hit.add("TCP flow table")
        scanners = ctx.scanners
        out = self._loss(ctx)
        out += self._refused(ctx, scanners)
        out += self._unanswered(ctx, scanners)
        out += self._latency(ctx)
        gaps = sum(p.acked_unseen for p in self.pairs.values())
        if gaps >= 20:
            ctx.warn("capture_gaps", f"The capture missed about {gaps} TCP segments.",
                     "Receivers acknowledged data that never appears in the capture. NetTriage does not count these "
                     "as network loss.")
        return out

    def _loss(self, ctx: Context) -> list[Finding]:
        # Resends on paths with an MTU problem are that problem's symptom, reported by the MTU detector.
        pairs = {k: v for k, v in self.pairs.items() if v.data and k not in ctx.mtu_pairs}
        total_data = sum(v.data for v in pairs.values())
        total_loss = sum(v.loss for v in pairs.values())
        total_flows = sum(v.flows for v in pairs.values())
        if total_data < 30 or total_loss < 3:
            return []
        by_server: dict[str, list] = defaultdict(list)
        by_client: dict[str, list] = defaultdict(list)
        for (c, s), v in pairs.items():
            by_server[s].append((c, v))
            by_client[c].append((s, v))

        def rate(items):
            d = sum(v.data for _, v in items)
            return (sum(v.loss for _, v in items) / d) if d else 0.0, d

        candidates = []
        for kind, groups in (("server", by_server), ("client", by_client)):
            for comp, items in groups.items():
                r, d = rate(items)
                events = sum(v.loss for _, v in items)
                lossy_peers = sum(1 for _, v in items if v.data and v.loss / v.data >= 0.02)
                rest_d = total_data - d
                rest_r = (total_loss - events) / rest_d if rest_d else 0.0
                if events >= 3 and d >= 30 and r >= 0.02 and (rest_d == 0 or r >= 3 * max(rest_r, 0.002)):
                    candidates.append((events, kind, comp, items, r, d, rest_r, lossy_peers))
        overall = total_loss / total_data
        findings: list[Finding] = []
        if not candidates:
            if overall >= 0.03 and total_loss >= 10:
                candidates = [(total_loss, "all", "all traffic", list(pairs.items()), overall, total_data, 0.0,
                               len(pairs))]
            else:
                return []
        candidates.sort(key=lambda c: (-c[0], c[1] != "server"))
        explained: set[tuple[str, str]] = set()
        for events, kind, comp, items, r, d, rest_r, lossy_peers in candidates[:3]:
            keys = {(c, comp) if kind == "server" else (comp, c) for c, _ in items} if kind != "all" \
                else set(pairs)
            new = keys - explained
            if sum(pairs[k].loss for k in new) < max(3, 0.5 * events):
                continue
            explained |= keys
            vs = [pairs[k] for k in keys]
            wan, lan = sum(v.wan for v in vs), sum(v.lan for v in vs)
            reorder, spurious = sum(v.reorder for v in vs), sum(v.spurious for v in vs)
            gaps = sum(v.acked_unseen for v in vs)
            flows = sum(v.flows for v in vs)
            peers = len(items)
            obs = [Observation("loss_rate", [f for v in vs for f in v.frames][:100],
                               {"rate": r, "events": events, "segments": d}, strength=min(1.0, r / 0.04))]
            if kind == "server" and lossy_peers >= 2:
                scope = f"Every device that talks to {comp} is affected ({lossy_peers} of {peers}), others are not"
                obs.append(Observation("localised", [], {"scope": scope}))
            elif kind == "client" and lossy_peers >= 2:
                scope = f"{comp} loses packets to {lossy_peers} different servers while other devices are fine"
                obs.append(Observation("localised", [], {"scope": scope}))
            if kind != "all" and rest_r < r / 3:
                obs.append(Observation("others_clean", [], {"other_rate": rest_r}))
            if flows >= 3:
                obs.append(Observation("many_flows", [], {"flows": flows, "total_flows": total_flows}))
            if reorder > events:
                obs.append(Observation("mostly_reordering", [], {"count": reorder}))
            if gaps > events:
                obs.append(Observation("capture_gaps", [], {"count": gaps}))
            if spurious > events / 2:
                obs.append(Observation("spurious", [], {"count": spurious}))
            diagnosis = LOSS.diagnose(obs, sufficient=events >= 3 and d >= 30)
            side = "wan" if wan >= lan else "lan"
            if kind == "server":
                where_short = f"on the path to {comp}"
                where_long = (f" somewhere between this network and {comp}" if side == "wan"
                              else f" on the office side of connections to {comp}")
                subject = f"exchanged with {comp}"
                cause = (f"Congestion or a fault on the route to {comp}, or {comp} itself is overloaded. Other "
                         "servers are fine, so the office network is not the problem.")
                fixes = (f"Test {comp} from another network; if it is slow there too, the problem is at their end.",
                         "If it is only slow from here, report the timings to your internet provider.",
                         "Nothing needs changing on the office PCs or switches.")
            elif kind == "client":
                where_short = f"on {comp}'s connection"
                where_long = f" between {comp} and the switch" if side == "lan" else ""
                subject = f"sent to and from {comp}"
                cause = (f"A problem specific to {comp}: a damaged or loose cable, a weak Wi-Fi signal, a failing "
                         "network card, or a busy switch port.")
                fixes = (f"Move {comp} closer to the Wi-Fi access point, or replace its network cable.",
                         f"Try a different switch port or network adapter for {comp}.",
                         f"Check {comp} for driver updates and for software saturating its connection.")
            else:
                where_short = "on all traffic"
                where_long = " on the office's internet connection"
                subject = "on this network"
                cause = "The shared uplink or the router is dropping packets (saturation, a faulty line or router)."
                fixes = ("Check the router and the internet line; reboot the router if it is overheating or "
                         "overloaded.", "Look for one device saturating the uplink (backups, large uploads).",
                         "Report the loss rate to your internet provider if it persists.")
            ctx_text = {"rate": r, "events": events, "segments": d, "flows": flows, "wan": wan, "lan": lan,
                        "reorder": reorder, "acked_unseen": gaps, "where_short": where_short,
                        "where_long": where_long, "subject": subject, "cause": cause, "fix1": fixes[0],
                        "fix2": fixes[1], "fix3": fixes[2]}
            first = min(v.first_ts for v in vs)
            last = max(v.last_ts for v in vs)
            ents = ([Entity(kind="ip", value=comp, role="affected " + kind)] if kind != "all" else []) + [
                Entity(kind="ip", value=c, role="peer") for c, _ in items[:5]]
            findings.append(build_finding(
                analyzer=self.name, diagnosis=diagnosis, narratives=LOSS_TEXT, ctx=ctx_text, entities=ents,
                frames=[f for v in vs for f in v.frames], key_packets=[k for v in vs for k in v.kp][:8],
                time_start=first, time_end=last,
                wireshark_filter=(f"ip.addr == {comp} && tcp.analysis.retransmission" if kind != "all"
                                  else "tcp.analysis.retransmission"),
                impact="multi_host" if kind != "client" else "single_host",
                max_frames=self.limits.max_evidence_frames,
            ))
        return findings

    def _refused(self, ctx: Context, scanners: set[str]) -> list[Finding]:
        out = []
        for (server, port), attempts in self.refused.items():
            attempts = [a for a in attempts if a[0] not in scanners]
            if not attempts:
                continue
            clients = {a[0] for a in attempts}
            n = len(attempts) + sum(a[3] for a in attempts)
            obs = [Observation("attempts", [a[2] for a in attempts], {"count": n, "port": port},
                               strength=min(1.0, n / 5))]
            if len(clients) >= 2:
                obs.append(Observation("clients", [], {"count": len(clients)}))
            if any(a[3] for a in attempts) or len(attempts) > len(clients):
                obs.append(Observation("retries"))
            up = self.ok_service.get((server, port))
            if up is not None and up < max(a[1] for a in attempts):
                obs.append(Observation("was_up"))
            diagnosis = REFUSED.diagnose(obs, sufficient=n >= 3)
            if diagnosis.verdict == Verdict.BENIGN and n < 2:
                continue
            ts = [a[1] for a in attempts]
            out.append(build_finding(
                analyzer=self.name, diagnosis=diagnosis, narratives=REFUSED_TEXT,
                ctx={"server": server, "port": port, "service": SERVICE_NAMES.get(port, "unknown service"),
                     "count": n, "clients": len(clients), "first": fmt_time(min(ts)), "last": fmt_time(max(ts))},
                entities=[Entity(kind="ip", value=server, role="server"), Entity(kind="port", value=str(port))]
                + [Entity(kind="ip", value=c, role="client") for c in sorted(clients)[:5]],
                frames=[a[2] for a in attempts], key_packets=[], time_start=min(ts), time_end=max(ts),
                wireshark_filter=f"ip.src == {server} && tcp.srcport == {port} && tcp.flags.reset == 1",
                impact="multi_host" if len(clients) >= 3 else "single_host",
                max_frames=self.limits.max_evidence_frames,
            ))
        return out

    def _outage(self, ctx: Context, public: dict[str, list]) -> Finding | None:
        """Many internet servers failing at once is one problem (the uplink), not many."""
        clients = {a[0] for attempts in public.values() for a in attempts}
        if len(public) < 3 or len(clients) < 2:
            return None
        onset = min(a[1] for attempts in public.values() for a in attempts)
        ok_before = sum(1 for (s, _), t in self.ok_service.items() if not is_private(s) and t < onset)
        attempts = [a for lst in public.values() for a in lst]
        retx = sum(a[3] for a in attempts)
        obs = [Observation("many_servers", [f for a in attempts for f in a[2]][:100], {"count": len(public)},
                           strength=min(1.0, len(public) / 5)),
               Observation("many_clients", [], {"count": len(clients)})]
        if ok_before >= 3:
            obs.append(Observation("worked_before", [], {"onset": fmt_time(onset)}))
        if ctx.gateway_silent():
            obs.append(Observation("silent_capture"))
        diagnosis = OUTAGE.diagnose(obs, sufficient=len(attempts) >= 5)
        return build_finding(
            analyzer=self.name, diagnosis=diagnosis, narratives=OUTAGE_TEXT,
            ctx={"onset": fmt_time(onset), "clients": len(clients), "count": len(public), "attempts": len(attempts),
                 "retx": retx, "ok_before": ok_before},
            entities=[Entity(kind="ip", value=s, role="unreachable server") for s in sorted(public)[:6]]
            + [Entity(kind="ip", value=c, role="affected client") for c in sorted(clients)[:6]],
            frames=[f for a in attempts for f in a[2]], key_packets=[],
            time_start=onset, time_end=max(a[1] for a in attempts),
            wireshark_filter="tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.analysis.retransmission",
            impact="critical_asset", max_frames=self.limits.max_evidence_frames,
        )

    def _unanswered(self, ctx: Context, scanners: set[str]) -> list[Finding]:
        out = []
        silent = ctx.silent_ips()
        answered_servers = {s for (s, _), _ in self.ok_service.items()}
        public = {s: [a for a in lst if a[0] not in scanners] for s, lst in self.unanswered.items()
                  if not is_private(s)}
        public = {s: lst for s, lst in public.items() if lst}
        outage = self._outage(ctx, public)
        if outage is not None:
            out.append(outage)
        for server, attempts in self.unanswered.items():
            if outage is not None and server in public:
                continue
            attempts = [a for a in attempts if a[0] not in scanners]
            if not attempts:
                continue
            clients = {a[0] for a in attempts}
            retx = sum(a[3] for a in attempts)
            frames = [f for a in attempts for f in a[2]]
            obs = [Observation("attempts", frames, {"count": len(attempts), "server": server},
                               strength=min(1.0, (len(attempts) + retx) / 5))]
            if retx >= 2:
                obs.append(Observation("backoff", [], {"retx": retx}))
            if len(clients) >= 2:
                obs.append(Observation("clients", [], {"count": len(clients)}))
            if server in ctx.dns_answers:
                obs.append(Observation("resolved"))
            if len(answered_servers - {server}) >= 2:
                obs.append(Observation("others_fine"))
            if server in silent or not is_private(server) and ctx.gateway_silent():
                obs.append(Observation("silent_capture"))
            # One connection that failed, even with retries, is worth showing but not alarming about.
            diagnosis = UNANSWERED.diagnose(obs, sufficient=len(attempts) >= 2 and len(attempts) + retx >= 3)
            ts = [a[1] for a in attempts]
            ports = ", ".join(str(p) for p in sorted({a[4] for a in attempts})[:4])
            out.append(build_finding(
                analyzer=self.name, diagnosis=diagnosis, narratives=UNANSWERED_TEXT,
                ctx={"server": server, "ports": ports, "count": len(attempts), "retx": retx,
                     "clients": len(clients), "first": fmt_time(min(ts)), "last": fmt_time(max(ts))},
                entities=[Entity(kind="ip", value=server, role="unreachable host")]
                + [Entity(kind="ip", value=c, role="client") for c in sorted(clients)[:5]],
                frames=frames, key_packets=[], time_start=min(ts), time_end=max(ts),
                wireshark_filter=f"ip.dst == {server} && tcp.flags.syn == 1 && tcp.flags.ack == 0",
                impact="multi_host" if len(clients) >= 3 else "single_host",
                max_frames=self.limits.max_evidence_frames,
            ))
        return out

    def _latency(self, ctx: Context) -> list[Finding]:
        medians = {s: statistics.median(v) for s, v in self.rtt.items() if len(v) >= 3}
        if len(medians) < 2:
            return []
        out = []
        for server, med in medians.items():
            others = [m for s, m in medians.items() if s != server]
            base = statistics.median(others)
            ratio = med / base if base > 0 else 0
            if med < 0.25 or ratio < 3:
                continue
            samples = sorted(self.rtt[server])
            p90 = samples[int(0.9 * (len(samples) - 1))]
            spread = samples[-1] - samples[0]
            obs = [Observation("absolute", [], {"median_ms": med * 1000, "samples": len(samples)},
                               strength=min(1.0, med / 0.5)),
                   Observation("relative", [], {"ratio": ratio, "base_ms": base * 1000})]
            if spread > 0.5 * med:
                obs.append(Observation("jitter", [], {"spread_ms": spread * 1000}))
            else:
                obs.append(Observation("steady"))
            diagnosis = LATENCY.diagnose(obs, sufficient=len(samples) >= 3)
            ctx_text = {"server": server, "median_ms": med * 1000, "p90_ms": p90 * 1000, "samples": len(samples),
                        "ratio": ratio, "base_ms": base * 1000}
            pairs = [v for (c, s), v in self.pairs.items() if s == server]
            out.append(build_finding(
                analyzer=self.name, diagnosis=diagnosis, narratives=LATENCY_TEXT, ctx=ctx_text,
                entities=[Entity(kind="ip", value=server, role="slow server")],
                frames=[], key_packets=[k for v in pairs for k in v.kp][:6],
                time_start=min((v.first_ts for v in pairs), default=ctx.first_ts or 0.0),
                time_end=max((v.last_ts for v in pairs), default=ctx.last_ts or 0.0),
                wireshark_filter=f"ip.addr == {server} && tcp.flags.syn == 1",
                impact="multi_host", max_frames=self.limits.max_evidence_frames,
            ))
        return out
