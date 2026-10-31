"""Path MTU problems.

Two signatures (see docs/research.md, Luckie & Stasiewicz, IMC 2010):

1. A router sends ICMP "fragmentation needed" (IPv4) or "packet too big" (IPv6).
   That only says a link on the path is smaller than usual. If the senders then
   shrink their segments and the data gets acknowledged, Path MTU Discovery is
   working and nothing is wrong. If they keep sending oversized segments, it is
   a fault.
2. A black hole: no ICMP arrives at all (a firewall drops it), so full-size
   segments carrying "don't fragment" are dropped and resent again and again,
   while small segments on the same connection get through.
"""

from __future__ import annotations

from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field

from ..config import Limits
from ..decode.model import ACK, Packet
from ..evidence.describe import key_packet
from ..reasoning.differential import Differential, HypothesisDef, Observation, Rule
from ..reasoning.finding import Narrative, build_finding
from ..schema import Entity, Finding, KeyPacket, Verdict
from .base import Context, Detector, is_private
from .tcp import sdiff

LARGE = 1000            # bytes of TCP payload; a "full-size" segment on any normal path
FALLBACK_MAX = 600      # Windows black-hole detection drops to 536-byte segments
MAX_TRACKED = 256


@dataclass
class Direction:
    first_ts: float
    last_ts: float = 0.0
    large: dict = field(default_factory=dict)     # seq -> [length, sends, first frame, df]
    small: dict = field(default_factory=dict)     # seq -> end
    segments: list = field(default_factory=list)  # (ts, payload, frame) for PMTUD adaptation checks
    acked: int | None = None
    ack_times: list = field(default_factory=list)
    large_retx: int = 0
    large_acked: int = 0
    small_acked: int = 0
    df_large: int = 0
    retx_frames: list = field(default_factory=list)
    first_retx_ts: float | None = None
    small_after_retx: int = 0      # small segments sent after full-size ones started failing
    fallback_acked: int = 0
    kp: list = field(default_factory=list)


@dataclass(slots=True)
class TooBig:
    ts: float
    frame: int
    router: str
    mtu: int
    version: int
    flow: tuple[str, int, str, int]
    kp: KeyPacket


BLACKHOLE = Differential(
    [
        HypothesisDef("blackhole", "Path MTU black hole", Verdict.FAULT, prior=-0.5),
        HypothesisDef("congestion", "Ordinary packet loss", Verdict.FAULT, prior=-0.5),
    ],
    [
        Rule("large_never_acked", "blackhole", 2.5, "{retx} resends of full-size packets, and not one was ever "
             "acknowledged"),
        Rule("small_ok", "blackhole", 2.0, "Small packets on the same connections were acknowledged ({count}), so "
             "the path works for anything small"),
        Rule("small_ok", "congestion", -2.0, "Congestion would drop small packets too"),
        Rule("df", "blackhole", 1.0, "The full-size packets carry 'don't fragment', so a smaller link has to drop "
             "them instead of splitting them"),
        Rule("no_icmp", "blackhole", 1.0, "No 'packet too big' message ever came back, which is what a firewall "
             "blocking ICMP looks like"),
        Rule("fallback", "blackhole", 1.5, "After the failed resends, {count} connection(s) switched to small "
             "(536-byte) packets, which got through: Windows' black-hole detection working around the problem"),
        Rule("many_flows", "blackhole", 0.5, "{flows} connections from {clients} device(s) show the same pattern"),
    ],
)

BLACKHOLE_TEXT = {
    "blackhole": Narrative(
        kind="mtu_blackhole",
        title="Large packets to {server} are silently dropped (MTU black hole)",
        simple=("Connections to {server} start fine, but as soon as {clients_text} send full-size packets, those "
                "packets vanish and are resent again and again. Small packets get through. A link on the way can't "
                "carry full-size packets, and the 'packet too big' warning that should come back is being blocked. "
                "Uploads and emails with attachments hang{fallback_note}."),
        technical=("{retx} retransmissions of {large} full-size segments (at least {min_large} bytes, DF set) in "
                   "{flows} flow(s), none acknowledged, while {small} small segments were acknowledged. No ICMP "
                   "fragmentation-needed or packet-too-big was seen for these paths.{fallback_tech}"),
        cause=("A link with a smaller MTU on the path (a VPN, PPPoE/DSL or another tunnel), combined with a "
               "firewall that drops ICMP 'fragmentation needed' messages. Senders never learn to use smaller "
               "packets."),
        fix=("Allow ICMP 'fragmentation needed' (type 3 code 4) and ICMPv6 'packet too big' through the router and "
             "firewall.",
             "Turn on TCP MSS clamping on the router (for example 1360 bytes on VPN or PPPoE links), so connections "
             "start with packets that fit.",
             "As a stopgap, lower the MTU of the affected devices or VPN interface (for example to 1400)."),
    ),
    "congestion": Narrative(
        kind="tcp_loss_large", title="Large packets to {server} are being lost",
        simple="Full-size packets to {server} are being lost and resent.",
        technical="{retx} retransmissions of full-size segments in {flows} flow(s).",
        cause="Congestion or a faulty link.", fix=("Check the link to {server} for errors and congestion.",)),
}

TOO_BIG = Differential(
    [
        HypothesisDef("working", "Path MTU Discovery working", Verdict.BENIGN, prior=0.5),
        HypothesisDef("broken", "Devices ignore 'packet too big'", Verdict.FAULT, prior=-0.5),
    ],
    [
        Rule("adapted", "working", 3.0, "{count} connection(s) switched to packets of at most {limit} bytes and "
             "their data was acknowledged"),
        Rule("adapted", "broken", -2.0, "The devices did shrink their packets"),
        Rule("not_adapted", "broken", 3.0, "{count} connection(s) kept sending packets larger than {limit} bytes "
             "after being told the limit"),
        Rule("not_adapted", "working", -2.0, "Some devices kept sending oversized packets"),
        Rule("repeated", "broken", 1.0, "{router} had to repeat the message {count} times"),
    ],
)

TOO_BIG_TEXT = {
    "working": Narrative(
        kind="pmtud_ok",
        title="Path MTU is {mtu} bytes towards {servers}, and devices adapt correctly",
        simple=("A link on the way to {servers} carries packets of at most {mtu} bytes, which is typical of VPNs and "
                "DSL lines. The router {router} said so, and the devices switched to smaller packets. Nothing to "
                "fix."),
        technical=("{icmp} ICMP {icmp_type} message(s) from {router} (MTU {mtu}); {adapted} quoted flow(s) then sent "
                   "segments of at most {limit} bytes that were acknowledged."),
        cause="A smaller-MTU link on the path; Path MTU Discovery handled it as designed.",
        fix=("Nothing to fix. MSS clamping on the router would avoid the first round of oversized packets.",),
    ),
    "broken": Narrative(
        kind="mtu_issue",
        title="Devices ignore 'packet too big' messages from {router}",
        simple=("{router} keeps telling devices that the path to {servers} only carries {mtu}-byte packets, but "
                "they keep sending larger ones, which are dropped. Connections to {servers} stall."),
        technical="{icmp} ICMP {icmp_type} message(s) (MTU {mtu}); {not_adapted} flow(s) still sent segments over "
                  "{limit} bytes afterwards.",
        cause="A host firewall or VPN client on the devices discards the ICMP message, or a broken network driver.",
        fix=("Allow ICMP 'fragmentation needed' / 'packet too big' on the devices' firewalls.",
             "Turn on TCP MSS clamping on the router.",
             "Lower the MTU of the affected devices' network or VPN interface."),
    ),
}


class MtuDetector(Detector):
    name = "mtu"

    def __init__(self, limits: Limits):
        super().__init__(limits)
        self.dirs: OrderedDict[tuple, Direction] = OrderedDict()
        self.too_big: list[TooBig] = []

    def on_packet(self, p: Packet) -> None:
        if p.icmp:
            i = p.icmp
            if ((i.version == 4 and i.type == 3 and i.code == 4) or (i.version == 6 and i.type == 2)) \
                    and i.mtu and i.inner_src and i.inner_sport is not None and len(self.too_big) < 2000:
                self.too_big.append(TooBig(p.ts, p.frame, p.ip.src if p.ip else "?", i.mtu, i.version,
                                           (i.inner_src, i.inner_sport, i.inner_dst, i.inner_dport), key_packet(p)))
            return
        t, ip = p.tcp, p.ip
        if t is None or ip is None:
            return
        if t.flags & ACK:
            rd = self.dirs.get((ip.dst, t.dport, ip.src, t.sport))
            if rd is not None:
                self._ack(rd, t.ack, p.ts)
        if t.payload_len == 0:
            return
        key = (ip.src, t.sport, ip.dst, t.dport)
        d = self.dirs.get(key)
        if d is None:
            d = self.dirs[key] = Direction(first_ts=p.ts)
            if len(self.dirs) > self.limits.max_flows:
                self.dirs.popitem(last=False)
        d.last_ts = p.ts
        size = t.payload_len
        if len(d.segments) < 400:
            d.segments.append((p.ts, size, p.frame))
        if size >= LARGE:
            entry = d.large.get(t.seq)
            if entry is None:
                if len(d.large) < MAX_TRACKED:
                    d.large[t.seq] = [size, 1, p.frame, ip.df]
                    d.df_large += ip.df
            else:
                entry[1] += 1
                d.large_retx += 1
                if d.first_retx_ts is None:
                    d.first_retx_ts = p.ts
                if len(d.retx_frames) < 40:
                    d.retx_frames.append(p.frame)
                if len(d.kp) < 4:
                    d.kp.append(key_packet(p, "full-size segment resent"))
        else:
            if d.first_retx_ts is not None and size <= FALLBACK_MAX:
                d.small_after_retx += 1
            if len(d.small) < MAX_TRACKED:
                d.small[t.seq] = ((t.seq + size) & 0xFFFFFFFF, size)

    @staticmethod
    def _ack(d: Direction, ackno: int, ts: float) -> None:
        if d.acked is not None and sdiff(ackno, d.acked) <= 0:
            return
        d.acked = ackno
        if len(d.ack_times) < 400:
            d.ack_times.append(ts)
        for seq in [s for s, e in d.large.items() if sdiff(ackno, (s + e[0]) & 0xFFFFFFFF) >= 0]:
            d.large.pop(seq)
            # Bytes acknowledged only after the sender fell back to small segments were
            # never delivered at full size.
            if not d.small_after_retx:
                d.large_acked += 1
        for seq in [s for s, (end, _) in d.small.items() if sdiff(ackno, end) >= 0]:
            _, size = d.small.pop(seq)
            d.small_acked += 1
            if d.first_retx_ts is not None and size <= FALLBACK_MAX and ts > d.first_retx_ts:
                d.fallback_acked += 1

    # --- end of capture -------------------------------------------------

    def finalize(self, ctx: Context) -> list[Finding]:
        icmp_paths = {(tb.flow[0], tb.flow[2]) for tb in self.too_big}
        out = self._blackholes(ctx, icmp_paths)
        out += self._too_big(ctx)
        return out

    def _blackholes(self, ctx: Context, icmp_paths: set[tuple[str, str]]) -> list[Finding]:
        by_remote: dict[str, list[tuple[tuple, Direction]]] = defaultdict(list)
        for key, d in self.dirs.items():
            src, _, dst, _ = key
            if d.large_retx >= 3 and d.large_acked == 0 and (src, dst) not in icmp_paths:
                remote = dst if is_private(src) or not is_private(dst) else src
                by_remote[remote].append((key, d))
        out = []
        for remote, items in by_remote.items():
            locals_ = sorted({k[0] if k[2] == remote else k[2] for k, _ in items})
            retx = sum(d.large_retx for _, d in items)
            large = sum(1 for _, d in items for _ in d.large) or len(items)
            small = sum(d.small_acked for _, d in items)
            fallback = [d for _, d in items if d.fallback_acked]
            obs = [Observation("large_never_acked", [f for _, d in items for f in d.retx_frames],
                               {"retx": retx}, strength=min(1.0, retx / 6))]
            if small:
                obs.append(Observation("small_ok", [], {"count": small}))
            if any(d.df_large for _, d in items):
                obs.append(Observation("df"))
            obs.append(Observation("no_icmp"))
            if fallback:
                obs.append(Observation("fallback", [], {"count": len(fallback)}))
            if len(items) >= 2:
                obs.append(Observation("many_flows", [], {"flows": len(items), "clients": len(locals_)}))
            diagnosis = BLACKHOLE.diagnose(obs, sufficient=retx >= 3 and small >= 1)
            for k, _ in items:
                ctx.mtu_pairs.add((k[0], k[2]))
                ctx.mtu_pairs.add((k[2], k[0]))
            ctx_text = {
                "server": remote, "clients_text": ", ".join(locals_[:3]) if len(locals_) <= 3
                else f"{len(locals_)} devices", "retx": retx, "large": large, "small": small, "flows": len(items),
                "min_large": LARGE,
                "fallback_note": (", or crawl along very slowly once Windows falls back to tiny packets"
                                  if fallback else ""),
                "fallback_tech": (f" {len(fallback)} flow(s) then succeeded with segments of at most "
                                  f"{FALLBACK_MAX} bytes." if fallback else ""),
            }
            frames = [f for _, d in items for f in d.retx_frames] + [
                e[2] for _, d in items for e in d.large.values()]
            out.append(build_finding(
                analyzer=self.name, diagnosis=diagnosis, narratives=BLACKHOLE_TEXT, ctx=ctx_text,
                entities=[Entity(kind="ip", value=remote, role="far end of the path")]
                + [Entity(kind="ip", value=c, role="affected device") for c in locals_[:5]],
                frames=frames, key_packets=[kp for _, d in items for kp in d.kp][:8],
                time_start=min(d.first_ts for _, d in items), time_end=max(d.last_ts for _, d in items),
                wireshark_filter=f"ip.addr == {remote} && tcp.len >= {LARGE} && tcp.analysis.retransmission",
                impact="multi_host" if len(locals_) >= 2 else "single_host",
                max_frames=self.limits.max_evidence_frames,
            ))
        return out

    def _too_big(self, ctx: Context) -> list[Finding]:
        groups: dict[tuple[str, int], list[TooBig]] = defaultdict(list)
        for tb in self.too_big:
            groups[(tb.router, tb.mtu)].append(tb)
        out = []
        for (router, mtu), msgs in groups.items():
            overhead = 40 if msgs[0].version == 4 else 60
            limit = mtu - overhead
            adapted, not_adapted, servers = 0, 0, set()
            per_flow = defaultdict(list)
            for tb in msgs:
                per_flow[tb.flow].append(tb)
            for flow, tbs in per_flow.items():
                src, sport, dst, dport = flow
                servers.add(dst)
                ctx.mtu_pairs.add((src, dst))
                ctx.mtu_pairs.add((dst, src))
                d = self.dirs.get((src, sport, dst, dport))
                if d is None:
                    continue
                t0 = tbs[0].ts
                after = [(ts, size) for ts, size, _ in d.segments if ts > t0 + 0.005]
                oversized = [s for _, s in after if s > limit]
                acked_after = any(ts > t0 for ts in d.ack_times)
                if after and not oversized and acked_after:
                    adapted += 1
                elif len(oversized) >= 2:
                    not_adapted += 1
            obs = []
            if adapted:
                obs.append(Observation("adapted", [], {"count": adapted, "limit": limit}))
            if not_adapted:
                obs.append(Observation("not_adapted", [], {"count": not_adapted, "limit": limit}))
            per_flow_max = max(len(v) for v in per_flow.values())
            if per_flow_max >= 3:
                obs.append(Observation("repeated", [], {"router": router, "count": per_flow_max}))
            diagnosis = TOO_BIG.diagnose(obs, sufficient=bool(adapted or not_adapted))
            names = sorted(servers)
            out.append(build_finding(
                analyzer=self.name, diagnosis=diagnosis, narratives=TOO_BIG_TEXT,
                ctx={"router": router, "mtu": mtu, "limit": limit, "servers": ", ".join(names[:3]),
                     "icmp": len(msgs), "adapted": adapted, "not_adapted": not_adapted,
                     "icmp_type": "fragmentation-needed" if msgs[0].version == 4 else "packet-too-big"},
                entities=[Entity(kind="ip", value=router, role="router reporting the limit")]
                + [Entity(kind="ip", value=s, role="far end of the path") for s in names[:4]],
                frames=[tb.frame for tb in msgs], key_packets=[tb.kp for tb in msgs[:6]],
                time_start=msgs[0].ts, time_end=msgs[-1].ts,
                wireshark_filter="icmp.type == 3 && icmp.code == 4" if msgs[0].version == 4 else "icmpv6.type == 2",
                impact="multi_host", max_frames=self.limits.max_evidence_frames,
            ))
        return out
