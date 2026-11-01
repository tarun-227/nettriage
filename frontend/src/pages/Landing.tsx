// The landing page: what NetTriage is for, what it catches, and what sets it apart, in eight sections.
// Scrolling down moves the page sideways. On narrow screens, or with reduced motion, the sections
// simply stack. Examples come from a real run of samples/scenarios/mitm_dns_combo.pcap; accuracy
// figures come from eval/results.md.
import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";
import { api, ApiError } from "../lib/api";
import { useMedia, useTitle } from "../lib/live";
import { href, navigate } from "../lib/router";
import { RadarDish } from "../components/Console";
import {
  CheckCircle, Cpu, Download, FileIcon, Fingerprint, Lock, ShieldAlert, Trash, Upload, WifiOff, Wrench,
} from "../components/icons";

const SECTIONS = ["Intro", "What it's for", "What it catches", "Fault vs attack", "Proof", "Blast radius", "Safe by design", "Get started"];
const N = SECTIONS.length;
const clamp = (x: number, a = 0, b = 1) => Math.max(a, Math.min(b, x));
const num = (i: number) => String(i + 1).padStart(2, "0");

// Packet bytes as a faint background texture (frame 1115 of the sample capture).
const BYTES = "a4 5e 60 02 c2 6b 08 00 27 3e 5a 11 08 06 00 01 08 00 06 04 00 02 08 00 27 3e 5a 11 c0 a8 01 01 a4 5e 60 02 c2 6b c0 a8 01 0c";

// Scroll snapping cancels the browser's own smooth scrolling, so a jump to a section is animated
// here, frame by frame, with snapping and smooth scroll-behavior paused until it lands.
const SNAP = "y proximity";
let snapping = false;
let gliding = 0;
function glide(top: number) {
  const root = document.documentElement;
  const from = window.scrollY;
  const dist = top - from;
  cancelAnimationFrame(gliding);
  if (Math.abs(dist) < 2) return;
  root.style.scrollSnapType = "none";
  root.style.scrollBehavior = "auto";
  const t0 = performance.now();
  const ms = Math.min(1100, 450 + Math.abs(dist) * 0.12);
  const step = (t: number) => {
    const k = Math.min(1, (t - t0) / ms);
    const eased = k < 0.5 ? 4 * k * k * k : 1 - (-2 * k + 2) ** 3 / 2;
    window.scrollTo(0, from + dist * eased);
    if (k < 1) { gliding = requestAnimationFrame(step); return; }
    gliding = 0;
    root.style.scrollBehavior = "";
    if (snapping) root.style.scrollSnapType = SNAP;
  };
  gliding = requestAnimationFrame(step);
}

// Runs the bundled sample and opens its report: the quickest way to see the tool work.
function useSample() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function run() {
    setBusy(true);
    setError(null);
    try {
      const { id } = await api.analyseSample("mitm_dns_combo.pcap");
      navigate(`/a/${id}`);
      window.scrollTo({ top: 0 });
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Something went wrong.");
      setBusy(false);
    }
  }
  return { busy, error, run };
}

export function Landing() {
  const story = useMedia("(min-width: 900px) and (min-height: 460px) and (prefers-reduced-motion: no-preference)");
  const track = useRef<HTMLDivElement>(null);
  const [p, setP] = useState(0);
  useTitle("NetTriage: broken or breached?");

  // Section k sits at k screen-heights down the track.
  const jump = (k: number) => {
    const el = track.current;
    if (el) glide(el.offsetTop + clamp(k, 0, N - 1) * window.innerHeight);
  };

  useEffect(() => {
    if (!story) return;
    let raf = 0;
    const read = () => {
      raf = 0;
      const el = track.current;
      if (!el) return;
      const max = el.offsetHeight - window.innerHeight;
      setP(max > 0 ? clamp(-el.getBoundingClientRect().top / max) : 0);
    };
    const onScroll = () => { if (!raf) raf = requestAnimationFrame(read); };
    // The page runs sideways, so the left and right arrow keys step through it too.
    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey || e.altKey || (e.key !== "ArrowRight" && e.key !== "ArrowLeft")) return;
      const el = track.current;
      if (!el) return;
      e.preventDefault();
      const here = Math.round((window.scrollY - el.offsetTop) / window.innerHeight);
      glide(el.offsetTop + clamp(here + (e.key === "ArrowRight" ? 1 : -1), 0, N - 1) * window.innerHeight);
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll);
    window.addEventListener("keydown", onKey);
    snapping = true;
    document.documentElement.style.scrollSnapType = SNAP;
    read();
    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
      window.removeEventListener("keydown", onKey);
      cancelAnimationFrame(raf);
      snapping = false;
      document.documentElement.style.scrollSnapType = "";
    };
  }, [story]);

  const f = p * (N - 1);
  const lp = (i: number) => (story ? f - i : 0);
  const slides = [Intro, WhatFor, Catches, FaultVsAttack, Proof, BlastRadius, SafeByDesign, GetStarted];
  const panels = slides.map((Slide, i) => (
    <Panel key={i} lp={lp(i)} story={story}><Slide lp={lp(i)} /></Panel>
  ));

  if (!story) {
    return (
      <div className="min-h-full bg-bg">
        <header className="sticky top-0 z-20 flex items-center justify-between gap-4 border-b border-line bg-bg/90 px-4 py-3 backdrop-blur sm:px-6">
          <Brand />
          <OpenButton />
        </header>
        <div className="console-bg">{panels}</div>
      </div>
    );
  }

  const idx = clamp(Math.round(f), 0, N - 1);
  return (
    <div ref={track} className="relative bg-bg" style={{ height: `${N * 100}vh` }}>
      {SECTIONS.map((s, i) => (
        <div key={s} aria-hidden="true" className="absolute left-0 h-px w-px" style={{ top: `${i * 100}vh`, scrollSnapAlign: "start" }} />
      ))}
      <div className="sticky top-0 h-screen overflow-hidden">
        <div className="console-bg absolute inset-0" style={{ backgroundPosition: `${-p * 1400}px 0` }} />
        <div aria-hidden="true" className="absolute left-0 top-[14%] whitespace-nowrap font-mono text-[128px] font-bold tracking-[0.05em] text-neon/[0.04]"
          style={{ transform: `translate3d(${p * -55}%, 0, 0)` }}>{BYTES}</div>

        <div className="absolute inset-0 flex will-change-transform" style={{ width: `${N * 100}%`, transform: `translate3d(${(-p * (N - 1) * 100) / N}%, 0, 0)` }}>
          {panels}
        </div>

        <header className="absolute inset-x-0 top-0 z-10 flex items-center gap-6 bg-gradient-to-b from-bg/90 to-transparent px-8 py-[18px]">
          <Brand />
          <div className="flex flex-1 items-center justify-center gap-3.5 font-mono text-[12px] tracking-[0.18em] text-muted">
            <span className="text-neon">{num(idx)} / {num(N - 1)}</span>
            <span className="uppercase text-ink">{SECTIONS[idx]}</span>
          </div>
          <OpenButton />
        </header>
        <div aria-hidden="true" className="absolute left-0 top-0 z-10 h-0.5 bg-neon shadow-glow" style={{ width: `${p * 100}%` }} />

        <nav aria-label="Sections" className="absolute inset-x-0 bottom-0 z-10 bg-gradient-to-t from-bg/90 to-transparent px-8 pb-6 pt-10">
          <div className="relative h-0.5 bg-line">
            <div className="absolute left-0 top-0 h-full bg-gradient-to-r from-neon/0 to-neon/80" style={{ width: `${p * 100}%` }} />
            <span className="absolute -top-1.5 -ml-[7px] h-3.5 w-3.5 rounded-full bg-neon shadow-[0_0_0_4px_rgb(var(--neon)/0.2),0_0_20px_rgb(var(--neon))]"
              style={{ left: `${p * 100}%` }} />
          </div>
          <div className="relative mt-2 h-5">
            {SECTIONS.map((s, k) => (
              <button key={s} type="button" onClick={() => jump(k)} aria-label={`Section ${k + 1}: ${s}`} aria-current={k === idx ? "step" : undefined}
                className={`absolute whitespace-nowrap font-mono text-[10.5px] uppercase tracking-[0.14em] transition-colors hover:text-neon ${k === idx ? "text-neon" : "text-muted"}
                  ${k === 0 ? "" : k === N - 1 ? "-translate-x-full" : "-translate-x-1/2"}`}
                style={{ left: `${(k / (N - 1)) * 100}%` }}>
                {s}
              </button>
            ))}
          </div>
        </nav>
      </div>
    </div>
  );
}

function Brand() {
  return (
    <a href={href("/")} className="flex items-center gap-2.5 font-mono text-[13px] font-bold tracking-[0.22em] text-neon">
      <span className="h-2 w-2 animate-pulse rounded-full bg-neon shadow-glow" /> NETTRIAGE
    </a>
  );
}

function OpenButton() {
  return (
    <a href={href("/app")} className="nt-btn nt-primary inline-flex shrink-0 items-center gap-2 rounded-[10px] bg-neon px-4 py-2.5 font-mono text-[13px] font-bold text-on-primary shadow-glow">
      Open dashboard <span className="nt-arrow">→</span>
    </a>
  );
}

// Each section swings in 3D as it passes: lp is its distance from the centre of the screen, in sections.
function Panel({ lp, story, children }: { lp: number; story: boolean; children: ReactNode }) {
  const a = Math.min(1, Math.abs(lp));
  const style: CSSProperties | undefined = story
    ? { transform: `translate3d(${lp * -22}%, 0, ${-a * 260}px) rotateY(${lp * -32}deg)`, opacity: Math.max(0.05, 1 - a * 0.95) }
    : undefined;
  return (
    <section className={`relative flex shrink-0 items-center justify-center [perspective:1400px] ${story
      ? "h-full w-[calc(100%/8)] px-16 pb-[110px] pt-24" : "min-h-[90svh] overflow-hidden border-b border-line px-4 py-20 sm:px-6"}`}>
      <div className="w-full max-w-[1200px]" style={style}>{children}</div>
    </section>
  );
}

// How far a piece has "arrived" as its section comes to the centre: 0 far away, 1 settled.
const arrive = (lp: number, delay = 0, speed = 3) => clamp((lp + 0.9 - delay) * speed);

const Eyebrow = ({ i, tone = "text-neon" }: { i: number; tone?: string }) => (
  <p className={`font-mono text-[12px] font-semibold uppercase tracking-[0.3em] ${tone}`}>{num(i)} · {SECTIONS[i]}</p>
);
const H2 = ({ children }: { children: ReactNode }) => (
  <h2 className="font-mono text-[clamp(32px,3.6vw,48px)] font-bold leading-[1.05] tracking-[-0.03em] text-white">{children}</h2>
);
const Lead = ({ children }: { children: ReactNode }) => <p className="max-w-[560px] text-[17px] leading-relaxed text-muted">{children}</p>;

function Intro({ lp }: { lp: number }) {
  const sample = useSample();
  return (
    <div className="grid items-center gap-12 lg:grid-cols-2">
      <div className="flex flex-col items-start gap-[22px]">
        <p className="font-mono text-[12px] font-semibold uppercase tracking-[0.3em] text-neon">Offline packet-capture diagnosis</p>
        <h1 className="font-mono text-[clamp(52px,7vw,92px)] font-bold uppercase leading-[0.92] tracking-[-0.035em] text-white">
          Broken<br />or <span className="nt-glitch text-attack">breached?</span>
        </h1>
        <p className="max-w-[500px] text-[18px] leading-relaxed text-muted">
          Drop a packet capture. NetTriage tells you if your network has a fault or is under attack, how sure it is, and the packets that prove it.
        </p>
        <div className="flex flex-wrap gap-3">
          <a href={href("/app")} className="nt-btn nt-primary inline-flex items-center gap-2.5 rounded-xl bg-neon px-[22px] py-3.5 font-mono text-[15px] font-bold text-on-primary shadow-glow">
            Open dashboard <span className="nt-arrow">→</span>
          </a>
          <button type="button" onClick={sample.run} disabled={sample.busy}
            className="nt-btn nt-ghost inline-flex items-center gap-2.5 rounded-xl border border-line bg-surface px-[22px] py-3.5 font-mono text-[15px] font-semibold disabled:opacity-60">
            {sample.busy ? "Analysing..." : "Try a sample"}
          </button>
        </div>
        {sample.error && <p role="alert" className="text-[13px] text-attack">{sample.error}</p>}
        <p className="flex items-center gap-3 font-mono text-[12px] tracking-[0.2em] text-muted">SCROLL <span className="nt-hint text-[18px] text-neon">→</span></p>
      </div>
      <div className="mx-auto w-[min(460px,100%)]" style={{ transform: `scale(${1 + Math.max(0, lp) * 0.5}) rotate(${lp * 25}deg)` }}>
        <RadarDish className="w-full" />
      </div>
    </div>
  );
}

// Raw bytes turn into a plain sentence, character by character, as the section arrives.
const VERDICT = "ATTACK 100% · 08:00:27:3e:5a:11 is impersonating the router";
const HEX = BYTES.replace(/ /g, "").slice(0, VERDICT.length);

function WhatFor({ lp }: { lp: number }) {
  const s = clamp((lp + 0.7) / 0.7);
  const k = Math.round(s * VERDICT.length);
  const steps = [
    { Icon: Upload, t: "Drop", d: "A .pcap or .pcapng from Wireshark or tcpdump, up to 500 MB." },
    { Icon: Cpu, t: "Analyse", d: "One pass through our own decoders, about 20,000 packets a second." },
    { Icon: CheckCircle, t: "Answer", d: "Fault or attack, how sure, why, and what to do next." },
  ];
  return (
    <div className="flex flex-col gap-9">
      <div className="flex flex-col gap-4">
        <Eyebrow i={1} />
        <H2>A capture has the answer.<br />Reading it takes an expert.</H2>
        <Lead>NetTriage reads every packet for you and writes down what it found, in plain words.</Lead>
      </div>
      <div className="overflow-hidden rounded-2xl border border-line bg-surface/85 px-5 py-4 font-mono text-[15px] shadow-lift">
        <span className="mr-3 text-[11px] tracking-[0.16em] text-muted">{s < 1 ? "DECODING" : "VERDICT"}</span>
        <span className="text-attack">{VERDICT.slice(0, k)}</span>
        <span className="text-muted/60">{HEX.slice(k)}</span>
      </div>
      <div className="grid gap-4 md:grid-cols-3">
        {steps.map(({ Icon, t, d }, i) => {
          const a = arrive(lp, i * 0.15);
          return (
            <div key={t} className="nt-lift rounded-2xl border border-line bg-surface p-6 shadow-card" style={{ opacity: a, transform: `translateY(${(1 - a) * 40}px)` }}>
              <span className="flex items-center gap-3">
                <span className="flex h-11 w-11 items-center justify-center rounded-full border border-neon font-mono text-[16px] font-bold text-neon shadow-glow">{i + 1}</span>
                <span className="text-neon"><Icon size={20} /></span>
              </span>
              <h3 className="mt-4 text-[18px] font-semibold text-white">{t}</h3>
              <p className="mt-1.5 leading-relaxed text-muted">{d}</p>
            </div>
          );
        })}
      </div>
    </div>
  );
}

const CATCHES = [
  { Icon: ShieldAlert, title: "Attacks", tone: "text-attack", border: "border-attack/40",
    items: ["ARP spoofing and man-in-the-middle", "Port scans, including stealth and slow", "Forged DNS answers", "DNS cache-poisoning floods", "Rogue DHCP servers", "Network sweeps"] },
  { Icon: Wrench, title: "Faults", tone: "text-fault", border: "border-fault/40",
    items: ["Packet loss, located to a link or server", "Duplicate IP addresses", "DNS down, failing or slow", "Refused or unreachable services", "Internet outages and high latency", "MTU black holes", "DHCP failures"] },
  { Icon: CheckCircle, title: "Ruled out", tone: "text-benign", border: "border-benign/40",
    items: ["Router failover (VRRP, HSRP)", "A swapped network card", "Ad blockers and CDN rotation", "Busy PCs and retries", "One-way captures", "Path MTU working normally"] },
];

function Catches({ lp }: { lp: number }) {
  return (
    <div className="flex flex-col gap-8">
      <div className="flex flex-col gap-4">
        <Eyebrow i={2} />
        <H2>Faults, attacks, and the<br />look-alikes it rules out</H2>
      </div>
      <div className="grid gap-4 [perspective:1200px] md:grid-cols-3">
        {CATCHES.map(({ Icon, title, tone, border, items }, i) => {
          const a = arrive(lp, i * 0.2);
          return (
            <div key={title} className={`nt-lift rounded-2xl border bg-surface p-6 shadow-card ${border}`}
              style={{ opacity: a, transform: `rotateY(${(1 - a) * -70}deg)`, transformOrigin: "left center" }}>
              <p className={`flex items-center gap-2.5 font-mono text-[13px] font-bold uppercase tracking-[0.2em] ${tone}`}><Icon size={18} /> {title}</p>
              <ul className="mt-4 flex flex-col gap-2.5 text-[14.5px]">
                {items.map((t) => <li key={t} className="flex gap-2.5"><span className={tone}>▸</span>{t}</li>)}
              </ul>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function FaultVsAttack({ lp }: { lp: number }) {
  const conf = clamp((lp + 0.7) / 0.7);
  const hyps = [
    { name: "ARP spoofing", w: conf * 100, c: "bg-attack" },
    { name: "Router failover", w: (1 - conf) * 45, c: "bg-benign" },
    { name: "Duplicate IP address", w: (1 - conf) * 35, c: "bg-fault" },
    { name: "Network card replaced", w: (1 - conf) * 20, c: "bg-benign" },
  ];
  const why = [
    ["+", "260 packets relayed to their real destination with the TTL lowered by one", "text-neon"],
    ["+", "42 ARP replies nobody asked for, sent straight to 2 hosts", "text-neon"],
    ["+", "The replies repeat every 2.0 s, like a spoofing tool", "text-neon"],
    ["✓", "Not router failover: failover announces once, to everyone, not to chosen hosts", "text-benign"],
  ];
  return (
    <div className="grid items-center gap-12 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
      <div className="flex flex-col gap-4">
        <Eyebrow i={3} />
        <H2>Every issue is weighed<br />against its look-alikes</H2>
        <Lead>Faults are consistent. Attacks have to lie. NetTriage scores every explanation and shows you why, and why not.</Lead>
      </div>
      <div className="flex flex-col gap-4">
        <div className="flex flex-col gap-2.5 rounded-2xl border border-line bg-surface/85 p-5 font-mono text-[12.5px]">
          {hyps.map((h) => (
            <div key={h.name} className="grid grid-cols-[190px_minmax(0,1fr)_48px] items-center gap-3">
              <span>{h.name}</span>
              <span className="h-2 overflow-hidden rounded-full bg-line"><span className={`block h-full rounded-full ${h.c}`} style={{ width: `${h.w}%` }} /></span>
              <span className="text-right text-muted">{Math.round(h.w)}%</span>
            </div>
          ))}
        </div>
        <ul className="flex flex-col gap-2 text-[14px]">
          {why.map(([mark, text, tone], k) => {
            const a = arrive(lp, k * 0.12, 4);
            return (
              <li key={text} className="flex gap-3 rounded-xl border border-line bg-surface/85 px-3.5 py-2.5"
                style={{ opacity: a, transform: `translateX(${(1 - a) * 50}px)` }}>
                <span className={`font-mono font-bold ${tone}`}>{mark}</span>{text}
              </li>
            );
          })}
        </ul>
        <p className="font-mono text-[11px] tracking-[0.14em] text-muted">FROM mitm_dns_combo.pcap</p>
      </div>
    </div>
  );
}

const ROOT = "fa5b1c85df1a78bcfc674717dc54f92029621edd4fc48c88007244b7cf3e638a";

function Proof({ lp }: { lp: number }) {
  const typed = Math.round(clamp((lp + 0.6) / 0.6) * ROOT.length);
  const rows = [["1115", "+0:19.6", "192.168.1.1 is at 08:00:27:3e:5a:11, unrequested"], ["1265", "+0:21.5", "the same claim, 2 s later"],
    ["1299", "+0:23.5", "DNS query relayed by 08:00:27:3e:5a:11, TTL 64 → 63"]];
  return (
    <div className="flex flex-col gap-8">
      <div className="flex flex-col gap-4">
        <Eyebrow i={4} />
        <H2>Proof you can check,<br />not a black box</H2>
        <Lead>Every finding points at the exact packets behind it, so anyone can check it in Wireshark.</Lead>
      </div>
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
        <div className="flex flex-col gap-3 rounded-2xl border border-line bg-surface p-5 shadow-card">
          <p className="flex items-center gap-2 text-[14px] font-semibold text-white"><FileIcon size={16} /> Wireshark frame numbers</p>
          <div className="overflow-hidden rounded-xl border border-line font-mono text-[12.5px]">
            {rows.map(([no, t, what], k) => {
              const a = arrive(lp, k * 0.12, 4);
              return (
                <div key={no} className="grid grid-cols-[60px_70px_minmax(0,1fr)] gap-3 border-b border-line px-3 py-2 last:border-b-0"
                  style={{ opacity: a, transform: `translateX(${(1 - a) * 40}px)` }}>
                  <span className="text-neon">{no}</span><span className="text-muted">{t}</span><span className="truncate">{what}</span>
                </div>
              );
            })}
          </div>
          <p className="break-all rounded-lg border border-line bg-bg px-3 py-2 font-mono text-[12px] text-amber">arp.src.hw_mac == 08:00:27:3e:5a:11 || (arp.src.proto_ipv4 == 192.168.1.1)</p>
          <div className="flex flex-wrap gap-2 font-mono text-[12px]">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-line px-3 py-1"><Download size={13} /> evidence.pcap · 82 packets</span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-attack/40 px-3 py-1 text-attack">MITRE ATT&amp;CK T1557.002 · ARP cache poisoning</span>
          </div>
        </div>
        <div className="flex flex-col gap-3 rounded-2xl border border-neon/35 bg-surface p-5 shadow-card">
          <p className="flex items-center gap-2 text-[14px] font-semibold text-white"><Lock size={16} /> Proof Pack</p>
          <p className="leading-relaxed text-muted">One zip with the report, the evidence packets and a hash of every file. Addresses become pseudonyms, packet contents are left out, and any later change is caught.</p>
          <p className="font-mono text-[11px] tracking-[0.14em] text-muted">ROOT HASH</p>
          <p className="break-all font-mono text-[13px] text-neon">{ROOT.slice(0, typed)}<span className="nt-caret">_</span></p>
          <p className="rounded-lg border border-line bg-bg px-3 py-2 font-mono text-[12px]"><span className="text-neon">$</span> nettriage verify pack.zip --root {ROOT.slice(0, 8)}…</p>
        </div>
      </div>
    </div>
  );
}

function BlastRadius({ lp }: { lp: number }) {
  const s = clamp((lp + 0.7) / 0.7);
  const stats = [
    { n: 3, label: "connections readable in full (HTTP)", tone: "text-attack" },
    { n: 5, label: "encrypted: server visible, contents private", tone: "text-benign" },
    { n: 20, label: "DNS packets seen: every name looked up", tone: "text-fault" },
    { n: 2, label: "names redirected to a fake address", tone: "text-attack" },
  ];
  return (
    <div className="grid items-center gap-12 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.15fr)]">
      <div className="flex flex-col gap-4">
        <Eyebrow i={5} tone="text-attack" />
        <H2>What the attacker<br />could see</H2>
        <Lead>When NetTriage finds an interception, it works out exactly what was exposed, and which passwords to change.</Lead>
      </div>
      <div className="flex flex-col gap-4 rounded-2xl border border-attack/40 bg-surface p-6 shadow-lift">
        <p className="text-[15px] leading-relaxed">
          <span className="font-mono text-attack">08:00:27:3e:5a:11</span> sat in the middle of <span className="font-mono">192.168.1.12</span>'s traffic for{" "}
          <span className="font-mono font-bold text-white">{Math.round(29 * s)} s</span>.
        </p>
        <div className="grid grid-cols-2 gap-3">
          {stats.map((x) => (
            <div key={x.label} className="rounded-xl border border-line bg-bg p-4">
              <p className={`glow-text font-mono text-[34px] font-bold leading-none ${x.tone}`}>{Math.round(x.n * s)}</p>
              <p className="mt-1.5 text-[13px] leading-snug text-muted">{x.label}</p>
            </div>
          ))}
        </div>
        <div className="flex h-2.5 overflow-hidden rounded-full bg-line" title="Connections: readable vs encrypted">
          <span className="bg-attack" style={{ width: `${(3 / 8) * 100 * s}%` }} />
          <span className="bg-benign/70" style={{ width: `${(5 / 8) * 100 * s}%` }} />
        </div>
        <p className="text-[13px] text-muted"><span className="font-semibold text-neon">Fix:</span> change passwords used over HTTP on github.com, docs.python.org and cdn.example.net, then flush 192.168.1.12's DNS cache.</p>
      </div>
    </div>
  );
}

const CHECKS = [
  { Icon: WifiOff, t: "Offline", d: "0 bytes sent anywhere" },
  { Icon: Fingerprint, t: "Signature check", d: "A renamed .exe is refused unread" },
  { Icon: Lock, t: "Bounded parser", d: "Every length checked, pointer loops refused" },
  { Icon: Cpu, t: "Isolated worker", d: "Killed if it runs too long" },
  { Icon: ShieldAlert, t: "Escaped output", d: "<script> in a hostname is just text" },
  { Icon: Trash, t: "Nothing kept", d: "Upload deleted after analysis" },
];

function SafeByDesign({ lp }: { lp: number }) {
  return (
    <div className="flex flex-col gap-8">
      <div className="flex flex-col gap-4">
        <Eyebrow i={6} />
        <H2>Built to be handed hostile files</H2>
        <Lead>A capture is untrusted input. NetTriage reads it like one, and keeps it on your computer.</Lead>
      </div>
      <div className="grid gap-3 font-mono sm:grid-cols-2 lg:grid-cols-3">
        {CHECKS.map(({ Icon, t, d }, k) => {
          const ok = arrive(lp, k * 0.1, 4) > 0.6;
          return (
            <div key={t} className={`nt-lift flex items-center gap-4 rounded-xl border bg-surface p-4 transition-colors duration-300 ${ok ? "border-neon/40" : "border-line"}`}>
              <span className={`transition-colors ${ok ? "text-neon" : "text-muted"}`}><Icon size={20} /></span>
              <span className="min-w-0 flex-1">
                <span className="block text-[14px] font-bold text-white">{t}</span>
                <span className="block text-[12px] text-muted">{d}</span>
              </span>
              <span className={`shrink-0 whitespace-pre text-[12px] font-bold transition-colors ${ok ? "glow-text text-neon" : "text-muted/50"}`}>{ok ? "[ OK ]" : "[ .. ]"}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function GetStarted({ lp }: { lp: number }) {
  const s = clamp((lp + 0.7) / 0.7);
  const stats = [
    [`${Math.round(135 * s)}/135`, "right verdicts on held-out captures", "text-neon"],
    ["0", "false alarms on 55 look-alikes", "text-neon"],
    [`${Math.round(20 * s)}k`, "packets per second", "text-amber"],
    ["0 B", "sent anywhere", "text-amber"],
  ];
  return (
    <div className="mx-auto flex max-w-[1100px] flex-col items-center gap-[30px] text-center">
      <Eyebrow i={7} />
      <h2 className="font-mono text-[clamp(40px,4.6vw,60px)] font-bold leading-none tracking-[-0.03em] text-white">Measured, not promised.</h2>
      <div className="grid w-full gap-px overflow-hidden rounded-[18px] border border-line bg-line sm:grid-cols-2 lg:grid-cols-4">
        {stats.map(([v, label, tone]) => (
          <div key={label} className="bg-surface p-[22px]">
            <p className={`glow-text font-mono text-[38px] font-bold ${tone}`}>{v}</p>
            <p className="mt-1 text-muted">{label}</p>
          </div>
        ))}
      </div>
      <p className="text-[12px] text-muted">Scored on labelled captures from our own network simulator. Real networks will differ. Test only networks you own.</p>
      <div className="flex flex-wrap justify-center gap-3">
        <a href={href("/app/new")} className="nt-btn nt-primary inline-flex items-center gap-2.5 rounded-xl bg-neon px-6 py-[15px] font-mono text-[16px] font-bold text-on-primary shadow-glow">
          Analyse a capture <span className="nt-arrow">→</span>
        </a>
        <a href={href("/app")} className="nt-btn nt-ghost inline-flex items-center gap-2.5 rounded-xl border border-line bg-surface px-6 py-[15px] font-mono text-[16px] font-semibold">
          Browse the sample library
        </a>
      </div>
    </div>
  );
}
