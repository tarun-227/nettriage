"""Port scans, by Threshold Random Walk (Jung, Paxson, Berger, Balakrishnan, IEEE S&P 2004).

For each source, every *first* contact with a (destination, port) is a success
(SYN/ACK or a UDP reply) or a failure (RST, ICMP unreachable, or silence for 3 s).
Wald's sequential probability ratio test multiplies the likelihood ratio by
(1-θ1)/(1-θ0) = 4 per failure and θ1/θ0 = 0.25 per success. It flags a scanner at
Λ ≥ β/α = 99, with the paper's θ0 = 0.8, θ1 = 0.2, α = 0.01, β = 0.99.

Our adaptations (see docs/research.md):
- (host, port) pairs instead of hosts only, so vertical scans count;
- a floor at η0 instead of stopping at "benign", so a host that browsed
  normally earlier can still be caught when it starts scanning;
- failures towards hosts that contacted the source first are ignored ("friendly hosts");
- the TRW result is one piece of evidence, weighed against an *outage*
  explanation: a client that can reach nothing also fails every first contact.
"""

from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass

from ..config import Limits
from ..decode.model import ACK, FIN, PSH, RST, SYN, URG, Packet
from ..evidence.describe import key_packet
from ..reasoning.differential import Differential, HypothesisDef, Observation, Rule
from ..reasoning.finding import Narrative, build_finding
from ..schema import Entity, Finding, KeyPacket, Verdict
from .arp import fmt_time
from .base import Context, Detector, is_private

THETA0, THETA1, ALPHA, BETA = 0.8, 0.2, 0.01, 0.99
ETA1 = BETA / ALPHA
ETA0 = (1 - BETA) / (1 - ALPHA)
STEP_FAIL = (1 - THETA1) / (1 - THETA0)
STEP_OK = THETA1 / THETA0
TIMEOUT = 3.0
COMMON_CLIENT_PORTS = {53, 80, 123, 443, 853, 993, 5223, 8080, 8443}


@dataclass(slots=True)
class Attempt:
    ts: float
    frame: int
    kind: str                # syn, stealth, udp
    outcome: str | None = None  # ok, rst, icmp
    half_open: bool = False


def _stealth_name(flags: int) -> str | None:
    """Name a flag combination that legitimate TCP never sends without ACK."""
    if flags & ACK:
        return None
    core = flags & (SYN | FIN | RST | PSH | URG)
    if core == 0:
        return "NULL"
    if core == FIN:
        return "FIN"
    if core == FIN | PSH | URG:
        return "Xmas"
    if core & SYN and core & (FIN | RST):
        return "SYN+FIN"
    if core in (SYN, RST, RST | PSH):
        return None
    return "invalid-flags"


DIFF = Differential(
    [
        HypothesisDef("scan", "Port scan", Verdict.ATTACK, prior=-1.0),
        HypothesisDef("outage", "Connectivity outage", Verdict.FAULT, prior=-1.0),
        HypothesisDef("noisy", "Misbehaving application", Verdict.BENIGN, prior=0.0),
        HypothesisDef("capture", "Replies missing from the capture", Verdict.BENIGN, prior=-1.0),
    ],
    [
        Rule("silent_capture", "capture", 5.0, "{pct:.0%} of the 'failed' targets sit behind a device whose "
             "replies are entirely missing from the capture"),
        Rule("silent_capture", "outage", -3.0, "The replies may exist but were not captured"),
        Rule("silent_capture", "scan", -1.0, "The replies may exist but were not captured"),
        Rule("trw", "scan", 3.0, "{fails} of {total} first contacts failed: the odds are {ratio} that this is not "
             "normal use (sequential test, threshold 99:1)"),
        Rule("trw", "noisy", -1.5, "Ordinary programs mostly connect to things that exist"),
        Rule("many_ports", "scan", 2.0, "{count} different ports tried on {target}"),
        Rule("many_ports", "outage", -1.0, "An outage doesn't make a device try dozens of ports on one host"),
        Rule("many_ports", "noisy", -1.0, "Applications use a few known ports, not dozens"),
        Rule("many_hosts", "scan", 1.5, "{count} different addresses tried on port {port}"),
        Rule("many_hosts", "noisy", 0.5, "Peer-to-peer apps also contact many addresses"),
        Rule("illegal_flags", "scan", 4.0, "{count} {style} probes, a flag combination normal TCP never sends"),
        Rule("illegal_flags", "outage", -3.0, "Broken connectivity doesn't produce invalid TCP flags"),
        Rule("illegal_flags", "noisy", -3.0, "Applications don't send invalid TCP flags"),
        Rule("half_open", "scan", 2.0, "{count} times the target accepted and the source hung up at once without "
             "sending data (a SYN scan's half-open probe)"),
        Rule("half_open", "outage", -2.0, "Those targets answered, so the network works"),
        Rule("half_open", "noisy", -2.0, "Applications use the connections they open"),
        Rule("fast", "scan", 0.7, "Probes every {gap_ms:.0f} ms on average, far faster than a person browses"),
        Rule("fingerprint", "scan", 1.0, "{text}"),
        Rule("targets_from_dns", "outage", 2.5, "{pct:.0%} of the failed targets were looked up in DNS first, as "
             "normal applications do"),
        Rule("targets_from_dns", "noisy", 1.0, "The targets came from DNS lookups"),
        Rule("targets_from_dns", "scan", -2.0, "Scanners pick addresses themselves instead of looking names up"),
        Rule("common_ports", "outage", 1.0, "Only everyday ports ({ports}) were involved"),
        Rule("common_ports", "scan", -0.8, "Only everyday ports were involved"),
        Rule("others_failing", "outage", 2.5, "{count} other device(s) were failing in the same way at the same time"),
        Rule("others_failing", "scan", -1.5, "Other devices fail too, which points at the network"),
    ],
)

TEXT = {
    "scan": Narrative(
        kind="port_scan",
        title="{src} is scanning {target_desc}",
        simple=("{src} tried {unit} {span_text}, and {fail_pct:.0%} of its attempts were refused or ignored. "
                "Normal programs connect to things that exist; this is something mapping your network for weak "
                "spots{style_note}."),
        technical=("Threshold Random Walk (Jung et al. 2004): {fails} failed and {oks} successful first contacts; "
                   "likelihood ratio {ratio} against benign behaviour, past the 99:1 threshold after {detect_n} "
                   "attempts at {detect_time}. {shape}{open_note}"),
        cause="A port scanner such as nmap, masscan or ZMap, run by someone on the network or by malware on {src}.",
        fix=("Identify {src} ({mac}) and find out who is using it.",
             "If nobody is authorised to scan this network, disconnect {src} and check it for malware.",
             "{open_fix}"),
    ),
    "outage": Narrative(
        kind="connectivity_outage",
        title="{src} cannot reach the services it needs",
        simple=("{src} tried {attempts} destinations and most never answered, but they were ordinary sites it "
                "had looked up first. That is a broken connection, not an attack."),
        technical="{fails} failed and {oks} successful first contacts; targets resolved via DNS; ports {ports}.",
        cause="The router, the internet line or a firewall is blocking or dropping the traffic.",
        fix=("Check the router and the internet connection.",
             "Check whether a firewall or proxy setting on {src} blocks outbound connections."),
    ),
    "capture": Narrative(
        kind="capture_one_directional",
        title="Replies to {src} are missing from the capture",
        simple="{src}'s connections look unanswered, but the capture contains nothing coming back from the "
               "devices it talks to. The capture is one-directional; the network is probably fine.",
        technical="{fails} first contacts without a captured reply; the replying side never transmits in this "
                  "capture.",
        cause="The mirror port or capture filter only copies one direction.",
        fix=("Capture again on a mirror port that copies both directions.",),
    ),
    "noisy": Narrative(
        kind="noisy_client",
        title="{src} makes many failed connections",
        simple="{src} has a lot of connections that fail, but the pattern looks like a misbehaving application "
               "rather than a scan.",
        technical="{fails} failed and {oks} successful first contacts.",
        cause="An application retrying stale servers, or peer-to-peer software.",
        fix=("Check which application on {src} is making the connections.",),
    ),
}


class PortScanDetector(Detector):
    name = "portscan"

    def __init__(self, limits: Limits):
        super().__init__(limits)
        self.attempts: dict[str, dict[tuple[str, int], Attempt]] = defaultdict(dict)
        self.n_attempts = 0
        self.contacted_by: dict[str, set[str]] = defaultdict(set)
        self.mac: dict[str, str] = {}
        self.windows: dict[str, Counter] = defaultdict(Counter)
        self.mss_only: Counter = Counter()
        self.zmap_id: Counter = Counter()
        self.stealth: dict[str, Counter] = defaultdict(Counter)
        self.kp: dict[str, list[KeyPacket]] = defaultdict(list)
        self.capped = False

    def _attempt(self, src: str, dst: str, port: int, p: Packet, kind: str) -> None:
        per = self.attempts[src]
        if (dst, port) in per:
            return
        if self.n_attempts >= self.limits.max_flows:
            self.capped = True
            return
        per[(dst, port)] = Attempt(p.ts, p.frame, kind)
        self.n_attempts += 1
        if p.link and p.link.src and src not in self.mac:
            self.mac[src] = p.link.src
        if len(self.kp[src]) < 8:
            self.kp[src].append(key_packet(p))

    def on_packet(self, p: Packet) -> None:
        ip = p.ip
        if ip is None:
            return
        if p.tcp:
            t = p.tcp
            flags = t.flags
            style = _stealth_name(flags)
            if flags & SYN and not flags & ACK and style is None:
                self.contacted_by[ip.dst].add(ip.src)
                self._attempt(ip.src, ip.dst, t.dport, p, "syn")
                self.windows[ip.src][t.window] += 1
                if t.mss is not None and t.wscale is None and not t.sack_ok:
                    self.mss_only[ip.src] += 1
                if ip.ident == 54321:
                    self.zmap_id[ip.src] += 1
                return
            if style is not None:
                self.stealth[ip.src][style] += 1
                self._attempt(ip.src, ip.dst, t.dport, p, "stealth")
                return
            # Responses: from the target back to the source of the attempt.
            a = self.attempts.get(ip.dst, {}).get((ip.src, t.sport))
            if a is not None and a.outcome is None:
                if flags & SYN and flags & ACK:
                    a.outcome = "ok"
                elif flags & RST:
                    a.outcome = "rst"
                return
            # The source hanging up on a fresh connection without data: half-open probe.
            if flags & RST and t.payload_len == 0:
                a = self.attempts.get(ip.src, {}).get((ip.dst, t.dport))
                if a is not None and a.outcome == "ok" and p.ts - a.ts < 1.0:
                    a.half_open = True
            return
        if p.udp and not p.dns and not p.dhcp:
            u = p.udp
            a = self.attempts.get(ip.dst, {}).get((ip.src, u.sport))
            if a is not None:
                if a.outcome is None:
                    a.outcome = "ok"
                return
            if ip.dst.endswith(".255") or ip.dst.startswith(("224.", "239.", "255.", "ff")):
                return
            self._attempt(ip.src, ip.dst, u.dport, p, "udp")
            return
        if p.icmp and p.icmp.type in (3, 1) and p.icmp.inner_src and p.icmp.inner_dport is not None:
            a = self.attempts.get(p.icmp.inner_src, {}).get((p.icmp.inner_dst, p.icmp.inner_dport))
            if a is not None and a.outcome is None:
                a.outcome = "icmp"

    def finalize(self, ctx: Context) -> list[Finding]:
        if self.capped:
            ctx.counters.state_caps_hit.add("connection-attempt table")
        end = ctx.last_ts or 0.0
        walks = {}
        for src, per in self.attempts.items():
            walks[src] = self._walk(src, per, end)
        out = []
        for src, w in walks.items():
            if w is None:
                continue
            others = sum(1 for s, o in walks.items() if s != src and o and o["unanswered"] >= 3
                         and o["first"] <= w["last"] and o["last"] >= w["first"])
            f = self._finding(src, w, others, ctx)
            if f:
                out.append(f)
                if f.verdict == Verdict.ATTACK:
                    ctx.scanners.add(src)
        return out

    def _walk(self, src: str, per: dict[tuple[str, int], Attempt], end: float) -> dict | None:
        lam, peak = 1.0, 1.0
        fails = oks = unanswered = 0
        detect = None
        failed_targets = []
        history = sorted(per.items(), key=lambda kv: kv[1].ts)
        friendly = self.contacted_by.get(src, set())
        for i, ((dst, port), a) in enumerate(history):
            if a.kind == "stealth":
                failed = True
            elif a.outcome == "ok":
                failed = False
            elif a.outcome in ("rst", "icmp"):
                failed = True
            elif a.kind == "syn" and end - a.ts >= TIMEOUT:
                failed = True
                unanswered += 1
            else:
                continue  # silent UDP, or too close to the end of the capture to judge
            if failed and dst in friendly:
                continue
            if failed:
                fails += 1
                failed_targets.append((dst, port))
                lam *= STEP_FAIL
            else:
                oks += 1
                lam *= STEP_OK
            lam = max(lam, ETA0)
            peak = max(peak, lam)
            if detect is None and lam >= ETA1:
                detect = (i + 1, a.ts)
        stealth = sum(self.stealth.get(src, {}).values())
        if detect is None and stealth < 5:
            return None
        times = [a.ts for _, a in history]
        return {"lam": peak, "fails": fails, "oks": oks, "unanswered": unanswered, "detect": detect,
                "history": history, "failed_targets": failed_targets, "first": times[0], "last": times[-1],
                "stealth": stealth}

    def _finding(self, src: str, w: dict, others_failing: int, ctx: Context) -> Finding | None:
        history = w["history"]
        total = w["fails"] + w["oks"]
        ports_by_dst: dict[str, set[int]] = defaultdict(set)
        dsts_by_port: dict[int, set[str]] = defaultdict(set)
        for (dst, port), _ in history:
            ports_by_dst[dst].add(port)
            dsts_by_port[port].add(dst)
        top_dst, top_ports = max(ports_by_dst.items(), key=lambda kv: len(kv[1]))
        top_port, top_dsts = max(dsts_by_port.items(), key=lambda kv: len(kv[1]))
        ratio = f"{w['lam']:,.0f} to 1" if w["lam"] < 1e6 else "more than a million to 1"
        obs = [Observation("trw", [a.frame for _, a in history[:60]],
                           {"fails": w["fails"], "total": total, "ratio": ratio},
                           strength=min(1.0, math.log10(max(w["lam"], 1.0)) / 4))]
        vertical = len(top_ports) >= 10
        if vertical:
            obs.append(Observation("many_ports", [], {"count": len(top_ports), "target": top_dst}))
        if len(top_dsts) >= 10:
            obs.append(Observation("many_hosts", [], {"count": len(top_dsts), "port": top_port}))
        stealth = self.stealth.get(src)
        if stealth:
            style, count = stealth.most_common(1)[0]
            obs.append(Observation("illegal_flags", [], {"count": sum(stealth.values()), "style": style},
                                   strength=min(1.0, sum(stealth.values()) / 5)))
        half_open = sum(1 for _, a in history if a.half_open)
        if half_open >= 2:
            obs.append(Observation("half_open", [a.frame for _, a in history if a.half_open][:20],
                                   {"count": half_open}))
        gaps = [b[1].ts - a[1].ts for a, b in zip(history, history[1:], strict=False)]
        if len(gaps) >= 5 and statistics.median(gaps) < 0.05:
            obs.append(Observation("fast", [], {"gap_ms": statistics.median(gaps) * 1000}))
        fp = self._fingerprint(src)
        if fp:
            obs.append(Observation("fingerprint", [], {"text": fp}))
        failed = w["failed_targets"]
        if failed:
            from_dns = sum(1 for d, _ in failed if d in ctx.dns_answers) / len(failed)
            if from_dns >= 0.5:
                obs.append(Observation("targets_from_dns", [], {"pct": from_dns}))
            fports = {p for _, p in failed}
            if fports <= COMMON_CLIENT_PORTS:
                obs.append(Observation("common_ports", [], {"ports": ", ".join(map(str, sorted(fports)))}))
        if others_failing >= 1:
            obs.append(Observation("others_failing", [], {"count": others_failing}))
        if failed:
            silent = ctx.silent_ips()
            gateway_silent = ctx.gateway_silent()
            hidden = sum(1 for d, _ in failed if d in silent or (gateway_silent and not is_private(d)))
            if hidden / len(failed) >= 0.5:
                obs.append(Observation("silent_capture", [], {"pct": hidden / len(failed)}))
        diagnosis = DIFF.diagnose(obs, sufficient=total >= 5 or w["stealth"] >= 5)

        span = w["last"] - w["first"]
        open_ports = sorted({p for (d, p), a in history if a.outcome == "ok" and d == top_dst})
        if vertical:
            target_desc, unit = f"{top_dst} for open ports", f"{len(top_ports)} ports on {top_dst}"
            shape = f"Vertical scan: {len(top_ports)} ports on {top_dst}."
        else:
            target_desc, unit = f"the network on port {top_port}", f"{len(top_dsts)} addresses on port {top_port}"
            shape = f"Horizontal scan: {len(top_dsts)} addresses, mostly port {top_port}."
        style_note = (f", using {stealth.most_common(1)[0][0]} probes that legitimate software never sends"
                      if stealth else "")
        detect_n, detect_ts = w["detect"] or (total, w["last"])
        ctx_text = {
            "src": src, "mac": self.mac.get(src, "unknown MAC"), "target_desc": target_desc,
            "attempts": len(history), "unit": unit,
            "span_text": f"in {span:.0f} seconds" if span >= 1 else "in under a second",
            "fail_pct": w["fails"] / total if total else 1.0, "style_note": style_note,
            "fails": w["fails"], "oks": w["oks"], "ratio": ratio, "detect_n": detect_n,
            "detect_time": fmt_time(detect_ts), "shape": shape,
            "open_note": f" Open: {', '.join(map(str, open_ports[:10]))}." if open_ports else "",
            "open_fix": (f"Make sure the services that answered on {top_dst} (ports "
                         f"{', '.join(map(str, open_ports[:8]))}) are patched and really need to be reachable."
                         if open_ports else "Review which devices this source could reach."),
            "ports": ", ".join(str(p) for p in sorted({p for _, p in failed})[:6]),
        }
        targets =sorted(ports_by_dst, key=lambda d: -len(ports_by_dst[d]))[:5]
        return build_finding(
            analyzer=self.name, diagnosis=diagnosis, narratives=TEXT, ctx=ctx_text,
            entities=[Entity(kind="ip", value=src, role="scanner")]
            + ([Entity(kind="mac", value=self.mac[src], role="scanner")] if src in self.mac else [])
            + [Entity(kind="ip", value=t, role="target") for t in targets],
            frames=[a.frame for _, a in history], key_packets=self.kp.get(src, []),
            time_start=w["first"], time_end=w["last"],
            wireshark_filter=f"ip.src == {src} && tcp.flags.ack == 0",
            impact="multi_host" if len(ports_by_dst) > 1 else "single_host",
            max_frames=self.limits.max_evidence_frames,
        )

    def _fingerprint(self, src: str) -> str:
        syns = sum(self.windows[src].values())
        if not syns:
            return ""
        if self.zmap_id[src] >= max(3, 0.8 * syns):
            return "IP ID fixed at 54321, a known ZMap signature"
        win, n = self.windows[src].most_common(1)[0]
        if win in (1024, 2048, 3072, 4096) and n >= max(3, 0.8 * syns) and self.mss_only[src] >= 0.8 * syns:
            return (f"SYNs use a {win}-byte window with only an MSS option, unlike any normal operating system "
                    "(consistent with nmap or masscan)")
        return ""
