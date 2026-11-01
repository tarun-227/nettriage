// The landing page: one real attack from samples/scenarios/mitm_dns_combo.pcap, told in seven chapters.
// Scrolling down moves the story sideways. On narrow screens, or with reduced motion, the chapters
// simply stack. Every number and byte here comes from that capture or from eval/results.md.
import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";
import { api, ApiError } from "../lib/api";
import { useMedia } from "../lib/live";
import { href, navigate } from "../lib/router";
import { RadarDish } from "../components/Console";
import { Activity, Bars, CheckCircle, Copy, Cpu, Download, FileIcon, List, ShieldAlert, Wrench } from "../components/icons";

const N = 7;
const CHAPTERS = ["Intro", "Your network", "Fault or attack", "The impostor", "The evidence", "The verdict", "Your turn"];
const clamp = (x: number, a = 0, b = 1) => Math.max(a, Math.min(b, x));
// Story position -> capture position: the impostor's first reply is frame 1115 at 0:19.6, the forged DNS answer 1705 at 0:29.2.
const KNOTS = [0, 0.5, 2 / 3, 1];
function lerp(ys: number[], x: number) {
  for (let i = 1; i < KNOTS.length; i++) {
    if (x <= KNOTS[i]) return ys[i - 1] + ((x - KNOTS[i - 1]) / (KNOTS[i] - KNOTS[i - 1])) * (ys[i] - ys[i - 1]);
  }
  return ys[ys.length - 1];
}

// Frame 1115 of the capture: the impostor's ARP reply. The highlighted bytes are the lie.
const FRAME_1115 = "a4 5e 60 02 c2 6b 08 00 27 3e 5a 11 08 06 00 01 08 00 06 04 00 02";
const LIE = "08 00 27 3e 5a 11 c0 a8 01 01";
const FRAME_TAIL = "a4 5e 60 02 c2 6b c0 a8 01 0c";

export function Landing() {
  const story = useMedia("(min-width: 960px) and (min-height: 640px) and (prefers-reduced-motion: no-preference)");
  const track = useRef<HTMLDivElement>(null);
  const [p, setP] = useState(0);

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
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll);
    document.documentElement.style.scrollSnapType = "y proximity";
    read();
    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
      cancelAnimationFrame(raf);
      document.documentElement.style.scrollSnapType = "";
    };
  }, [story]);

  const f = p * (N - 1);
  const lp = (i: number) => (story ? f - i : 0);
  const chapters = [Intro, Network, FaultOrAttack, Impostor, Evidence, Verdict, YourTurn];
  const panels = chapters.map((Chapter, i) => (
    <Panel key={i} lp={lp(i)} story={story}><Chapter lp={lp(i)} /></Panel>
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
  const frame = Math.max(1, Math.round(lerp([1, 1115, 1705, 3012], p)));
  const secs = lerp([0, 19.6, 29.2, 59.6], p);
  return (
    <div ref={track} className="relative bg-bg" style={{ height: `${N * 100}vh` }}>
      {CHAPTERS.map((c, i) => (
        <div key={c} aria-hidden="true" className="absolute left-0 h-px w-px" style={{ top: `${i * 100}vh`, scrollSnapAlign: "start" }} />
      ))}
      <div className="sticky top-0 h-screen overflow-hidden">
        <div className="console-bg absolute inset-0" style={{ backgroundPosition: `${-p * 1400}px 0` }} />
        <div aria-hidden="true" className="absolute left-0 top-[14%] whitespace-nowrap font-mono text-[128px] font-bold tracking-[0.05em] text-neon/[0.045]"
          style={{ transform: `translate3d(${p * -55}%, 0, 0)` }}>
          {FRAME_1115.slice(0, 17)} <span className="text-attack/[0.12]">08 00 27 3e 5a 11</span> {FRAME_1115.slice(36)}{" "}
          <span className="text-attack/[0.12]">{LIE}</span> {FRAME_TAIL}
        </div>

        <div className="absolute inset-0 flex will-change-transform" style={{ width: `${N * 100}%`, transform: `translate3d(${(-p * (N - 1) * 100) / N}%, 0, 0)` }}>
          {panels}
        </div>

        <header className="absolute inset-x-0 top-0 z-10 flex items-center gap-6 bg-gradient-to-b from-bg/90 to-transparent px-8 py-[18px]">
          <Brand />
          <div className="flex flex-1 items-center justify-center gap-3.5 font-mono text-[12px] tracking-[0.18em] text-muted">
            <span className="text-neon">0{idx + 1} / 07</span>
            <span className="uppercase text-ink">{CHAPTERS[idx]}</span>
            <span className="flex gap-1.5">
              {CHAPTERS.map((c, k) => (
                <span key={c} className={`h-1.5 rounded-full transition-all duration-300 ${k <= idx ? "bg-neon" : "bg-line"}`}
                  style={{ width: k === idx ? 22 : 6 }} />
              ))}
            </span>
          </div>
          <OpenButton />
        </header>
        <div aria-hidden="true" className="absolute left-0 top-0 z-10 h-0.5 bg-neon shadow-glow" style={{ width: `${p * 100}%` }} />

        <footer aria-hidden="true" className="absolute inset-x-0 bottom-0 z-10 bg-gradient-to-t from-bg/90 to-transparent px-8 pb-[26px]">
          <div className="mb-2.5 flex justify-between font-mono text-[11.5px] tracking-[0.16em] text-muted">
            <span>FRAME <span className="text-neon">{frame.toLocaleString("en-US")}</span> / 3,012</span>
            <span>T+<span className="text-neon">{Math.floor(secs / 60)}:{(secs % 60).toFixed(1).padStart(4, "0")}</span></span>
          </div>
          <div className="relative h-0.5 bg-line">
            <div className="absolute left-0 top-0 h-full bg-gradient-to-r from-neon/0 to-neon/80" style={{ width: `${p * 100}%` }} />
            <Marker at={50} lit={p >= 0.5} label="#1115 impostor" />
            <Marker at={66.7} lit={p >= 2 / 3} label="#1705 DNS forged" />
            <span className="absolute -top-1.5 -ml-[7px] h-3.5 w-3.5 rounded-full bg-neon shadow-[0_0_0_4px_rgb(var(--neon)/0.2),0_0_20px_rgb(var(--neon))]"
              style={{ left: `${p * 100}%` }} />
          </div>
        </footer>
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

function Marker({ at, lit, label }: { at: number; lit: boolean; label: string }) {
  return (
    <>
      <span className="absolute -top-[5px] h-3 w-0.5 bg-attack" style={{ left: `${at}%`, boxShadow: lit ? "0 0 14px rgb(var(--attack))" : "none" }} />
      <span className="absolute top-3 -translate-x-1/2 whitespace-nowrap font-mono text-[10.5px] text-attack" style={{ left: `${at}%` }}>{label}</span>
    </>
  );
}

// Each chapter swings in 3D as it passes: lp is its distance from the centre of the screen, in chapters.
function Panel({ lp, story, children }: { lp: number; story: boolean; children: ReactNode }) {
  const a = Math.min(1, Math.abs(lp));
  const style: CSSProperties | undefined = story
    ? { transform: `translate3d(${lp * -22}%, 0, ${-a * 260}px) rotateY(${lp * -32}deg)`, opacity: Math.max(0.05, 1 - a * 0.95) }
    : undefined;
  return (
    <section className={`relative flex shrink-0 items-center justify-center [perspective:1400px] ${story
      ? "h-full w-[calc(100%/7)] px-16 pb-[120px] pt-24" : "min-h-[90svh] overflow-hidden border-b border-line px-4 py-20 sm:px-6"}`}>
      <div className="w-full max-w-[1200px]" style={style}>{children}</div>
    </section>
  );
}

const Eyebrow = ({ children, tone = "text-neon" }: { children: ReactNode; tone?: string }) => (
  <p className={`font-mono text-[12px] font-semibold uppercase tracking-[0.3em] ${tone}`}>{children}</p>
);
const H2 = ({ children }: { children: ReactNode }) => (
  <h2 className="font-mono text-[clamp(36px,4vw,52px)] font-bold leading-[1.03] tracking-[-0.03em] text-white">{children}</h2>
);

function Intro({ lp }: { lp: number }) {
  return (
    <div className="grid items-center gap-12 lg:grid-cols-2">
      <div className="flex flex-col items-start gap-[22px]">
        <Eyebrow>Case file · mitm_dns_combo.pcap</Eyebrow>
        <h1 className="font-mono text-[clamp(52px,7vw,92px)] font-bold uppercase leading-[0.92] tracking-[-0.035em] text-white">
          Broken<br />or <span className="nt-glitch text-attack">breached?</span>
        </h1>
        <p className="max-w-[460px] text-[18px] leading-relaxed text-muted">Scroll through a real capture and watch NetTriage catch the lie.</p>
        <p className="mt-2 flex items-center gap-3 font-mono text-[13px] tracking-[0.2em] text-neon">SCROLL <span className="nt-hint text-[22px]">→</span></p>
      </div>
      <div className="mx-auto w-[min(460px,100%)]" style={{ transform: `scale(${1 + Math.max(0, lp) * 0.5}) rotate(${lp * 25}deg)` }}>
        <RadarDish className="w-full" />
      </div>
    </div>
  );
}

function Node({ icon, name, sub, className = "", style, tone = "border-line", sweep = true }: {
  icon: ReactNode; name: string; sub: string; className?: string; style?: CSSProperties; tone?: string; sweep?: boolean;
}) {
  return (
    <div className={`nt-node ${sweep ? "nt-float" : ""} absolute w-[140px] rounded-[14px] border bg-surface p-3 text-center ${tone} ${className}`} style={style}>
      <span className="flex justify-center">{icon}</span>
      <span className="mt-1.5 block text-[13px] font-semibold text-white">{name}</span>
      <span className="font-mono text-[11px] text-muted">{sub}</span>
    </div>
  );
}

function Network() {
  return (
    <div className="grid items-center gap-14 lg:grid-cols-2">
      <div className="flex flex-col gap-[18px]">
        <Eyebrow>01 · Your network</Eyebrow>
        <H2>8 devices.<br />3,012 packets.<br />60 seconds.</H2>
        <p className="max-w-[440px] text-[17px] leading-relaxed text-muted">Every packet makes a claim: who sent it, and where it's going. Almost all of them are honest.</p>
      </div>
      <div className="relative mx-auto h-[400px] w-full max-w-[600px]">
        <svg aria-hidden="true" className="absolute inset-0 h-full w-full" viewBox="0 0 600 400" preserveAspectRatio="none">
          {[[90, 70], [510, 70], [90, 330], [510, 330]].map(([x, y]) => (
            <line key={`${x}-${y}`} className="nt-flow" x1="300" y1="200" x2={x} y2={y} stroke="rgb(var(--neon))" strokeWidth="2" strokeOpacity="0.6" />
          ))}
        </svg>
        <div className="nt-node absolute left-1/2 top-1/2 w-[150px] -translate-x-1/2 -translate-y-1/2 rounded-2xl border border-neon bg-surface p-4 text-center shadow-glow">
          <span className="flex justify-center text-neon"><Activity size={26} /></span>
          <span className="mt-2 block font-semibold text-white">Router</span>
          <span className="font-mono text-[11.5px] text-muted">192.168.1.1</span>
        </div>
        <Node className="left-[2%] top-[4%]" icon={<Cpu size={22} />} name="PC" sub="192.168.1.12" />
        <Node className="right-[2%] top-[4%]" style={{ animationDelay: "-1.5s" }} icon={<Bars size={22} />} name="File server" sub="on the LAN" />
        <Node className="bottom-[4%] left-[2%]" style={{ animationDelay: "-3s" }} icon={<FileIcon size={22} />} name="Laptop" sub='"laptop"' />
        <Node className="bottom-[4%] right-[2%]" style={{ animationDelay: "-4s" }} icon={<List size={22} />} name="+ 4 more" sub="phones, printers" />
      </div>
    </div>
  );
}

function Dots({ bad }: { bad: boolean }) {
  return (
    <div aria-hidden="true" className="mt-[22px] flex gap-3">
      {Array.from({ length: 7 }, (_, k) => (
        <span key={k} className={`h-3.5 w-3.5 rounded ${bad ? (k === 3 ? "nt-liar bg-attack" : "bg-neon") : `bg-fault ${k === 1 || k === 4 ? "nt-lost" : ""}`}`}
          style={!bad && k === 4 ? { animationDelay: "-1.2s" } : undefined} />
      ))}
    </div>
  );
}

function FaultOrAttack({ lp }: { lp: number }) {
  return (
    <div className="flex flex-col items-center gap-9">
      <div className="text-center">
        <Eyebrow>02 · Fault or attack</Eyebrow>
        <div className="mt-3.5"><H2>Same symptoms.<br />Opposite problems.</H2></div>
      </div>
      <div className="grid w-full gap-6 md:grid-cols-2">
        <div className="rounded-[20px] border border-fault/45 bg-[linear-gradient(160deg,rgb(var(--fault)/0.08),rgb(var(--surface))_60%)] p-7 shadow-lift"
          style={{ transform: `translateY(${lp * -160}px) rotate(${lp * -6}deg)` }}>
          <p className="flex items-center gap-2.5 font-mono text-[14px] font-bold tracking-[0.2em] text-fault"><Wrench size={20} /> FAULT</p>
          <h3 className="mt-3.5 text-[26px] font-bold text-white">Something broke.</h3>
          <p className="mt-2 text-[15.5px] leading-relaxed text-muted">A cable drops packets. A server stops answering. Everyone still tells the truth.</p>
          <Dots bad={false} />
        </div>
        <div className="rounded-[20px] border border-attack/50 bg-[linear-gradient(160deg,rgb(var(--attack)/0.1),rgb(var(--surface))_60%)] p-7 shadow-lift"
          style={{ transform: `translateY(${lp * 160}px) rotate(${lp * 6}deg)` }}>
          <p className="flex items-center gap-2.5 font-mono text-[14px] font-bold tracking-[0.2em] text-attack"><ShieldAlert size={20} /> ATTACK</p>
          <h3 className="mt-3.5 text-[26px] font-bold text-white">Someone is lying.</h3>
          <p className="mt-2 text-[15.5px] leading-relaxed text-muted">A device claims to be something it isn't. The story stops adding up.</p>
          <Dots bad />
        </div>
      </div>
    </div>
  );
}

function Impostor({ lp }: { lp: number }) {
  const claims = [["0:19.6", 0.8], ["0:21.5", 0.5], ["0:23.5", 0.2]] as const;
  const red = clamp((lp + 0.9) * 1.5);
  return (
    <div className="grid items-center gap-12 lg:grid-cols-2">
      <div className="flex flex-col gap-[18px]">
        <Eyebrow tone="text-attack">03 · The impostor</Eyebrow>
        <H2>At 0:19.6,<br />a device<br />starts <span className="text-attack">lying.</span></H2>
        <p className="max-w-[460px] text-[17px] leading-relaxed text-muted">
          08:00:27:3e:5a:11 tells the PC "I am the router", every 2 seconds. The PC believes it, and its traffic starts flowing through the impostor.
        </p>
        <div className="mt-1.5 break-all rounded-xl border border-line bg-surface/85 px-4 py-3.5 font-mono text-[13px] leading-[1.7]">
          <span className="mb-1 block text-[11px] tracking-[0.16em] text-muted">FRAME 1115 · ARP REPLY</span>
          <span className="text-muted">{FRAME_1115} </span>
          <span className="bg-attack/[0.12] text-attack">{LIE}</span>
          <span className="text-muted"> {FRAME_TAIL}</span>
          <span className="mt-1.5 block text-[12px] text-attack">↑ "192.168.1.1 is at 08:00:27:3e:5a:11". It isn't.</span>
        </div>
      </div>
      <div className="relative mx-auto h-[420px] w-full max-w-[600px]">
        <svg aria-hidden="true" className="absolute inset-0 h-full w-full" viewBox="0 0 600 420" preserveAspectRatio="none">
          <line x1="110" y1="90" x2="490" y2="90" stroke="rgb(var(--muted))" strokeWidth="2" strokeDasharray="4 8" strokeOpacity={1 - red * 0.8} />
          <path className="nt-flow-fast" d="M 110 110 L 300 320 L 490 110" fill="none" stroke="rgb(var(--attack))" strokeWidth="3" strokeOpacity={red} />
        </svg>
        <Node sweep={false} className="left-0 top-10 w-[150px]" icon={<Cpu size={22} />} name="PC" sub="192.168.1.12" />
        <Node sweep={false} className="right-0 top-10 w-[150px]" tone="border-neon" icon={<span className="text-neon"><Activity size={22} /></span>}
          name="Real router" sub="3c:52:82:10:00:01" />
        <div className="nt-liar absolute bottom-5 left-1/2 w-[180px] -translate-x-1/2 rounded-[14px] border border-attack bg-surface p-3.5 text-center">
          <span className="flex justify-center text-attack"><ShieldAlert size={22} /></span>
          <span className="mt-1.5 block font-semibold text-white">Impostor</span>
          <span className="font-mono text-[11px] text-attack">08:00:27:3e:5a:11</span>
        </div>
        <div className="absolute left-1/2 top-[150px] flex -translate-x-1/2 flex-col gap-1.5 whitespace-nowrap font-mono text-[12px]">
          {claims.map(([t, at]) => {
            const s = clamp((lp + at) * 3);
            return (
              <span key={t} className="rounded-full border border-attack/50 bg-surface/90 px-2.5 py-1 text-attack"
                style={{ opacity: s, transform: `translateX(${(1 - s) * 40}px)` }}>{t} · "I am 192.168.1.1"</span>
            );
          })}
        </div>
      </div>
    </div>
  );
}

const EVIDENCE = ["42 ARP replies nobody asked for", "260 packets relayed, TTL lowered by one",
  "Claims 2 addresses that aren't its own", "Repeats every 2.0 s, like a spoofing tool"];

function Evidence({ lp }: { lp: number }) {
  const conf = clamp((lp + 0.7) / 0.7);
  const hyps = [
    { name: "ARP spoofing", w: conf * 100, c: "bg-attack" },
    { name: "Router failover", w: (1 - conf) * 45, c: "bg-benign" },
    { name: "Duplicate IP address", w: (1 - conf) * 35, c: "bg-fault" },
    { name: "Network card replaced", w: (1 - conf) * 20, c: "bg-benign" },
  ];
  return (
    <div className="grid items-center gap-12 lg:grid-cols-2">
      <div className="mx-auto flex w-[min(380px,100%)] flex-col items-center">
        <RadarDish tone="attack" active className="w-full"
          blips={[{ x: 66, y: 32, d: 0.3, tone: "attack" }, { x: 30, y: 60, d: 1.5, tone: "attack" }, { x: 52, y: 70, d: 0.9, tone: "attack" }]} />
        <p className="-mt-6 font-mono text-[12px] tracking-[0.2em] text-muted">WEIGHING 4 EXPLANATIONS<span className="nt-caret">_</span></p>
      </div>
      <div className="flex flex-col gap-[18px]">
        <Eyebrow>04 · The evidence</Eyebrow>
        <H2>Lies leave<br />contradictions.</H2>
        <ul className="flex flex-col gap-2 text-[15px]">
          {EVIDENCE.map((text, k) => {
            const s = clamp((lp + 0.9 - k * 0.15) * 4);
            return (
              <li key={text} className="flex gap-3 rounded-xl border border-line bg-surface/85 px-3.5 py-2.5"
                style={{ opacity: s, transform: `translateX(${(1 - s) * 60}px)` }}>
                <span className="font-mono font-bold text-neon">+</span>{text}
              </li>
            );
          })}
        </ul>
        <div className="flex flex-col gap-2.5 rounded-[14px] border border-line bg-surface/85 p-4 font-mono text-[12.5px]">
          {hyps.map((h) => (
            <div key={h.name} className="grid grid-cols-[190px_minmax(0,1fr)_48px] items-center gap-3">
              <span>{h.name}</span>
              <span className="h-2 overflow-hidden rounded-full bg-line"><span className={`block h-full rounded-full ${h.c}`} style={{ width: `${h.w}%` }} /></span>
              <span className="text-right text-muted">{Math.round(h.w)}%</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function Verdict({ lp }: { lp: number }) {
  const s = clamp(-lp * 2.2);
  return (
    <div className="mx-auto flex max-w-[980px] flex-col items-center gap-[26px] text-center">
      <Eyebrow tone="text-attack">05 · The verdict</Eyebrow>
      <div className="rounded-[14px] border-4 border-attack px-10 py-3.5 font-mono text-[clamp(56px,7vw,96px)] font-bold leading-none tracking-[0.08em] text-attack
        shadow-[0_0_60px_-10px_rgb(var(--attack)/0.6),inset_0_0_40px_-10px_rgb(var(--attack)/0.4)] [text-shadow:0_0_30px_rgb(var(--attack)/0.6)]"
        style={{ transform: `scale(${1 + s * 1.6}) rotate(${-6 - s * 14}deg)`, opacity: 1 - s }}>ATTACK</div>
      <p className="font-mono text-[16px]"><span className="font-bold text-attack">100% confident</span> · critical</p>
      <h2 className="max-w-[820px] text-[clamp(24px,2.6vw,32px)] font-bold leading-tight text-white">08:00:27:3e:5a:11 is impersonating the router</h2>
      <div className="flex flex-wrap justify-center gap-2.5 font-mono text-[13px]">
        <span className="inline-flex items-center gap-2 rounded-full border border-line bg-surface px-3.5 py-2"><Download size={15} /> evidence.pcap · 82 packets</span>
        <span className="inline-flex items-center gap-2 rounded-full border border-line bg-surface px-3.5 py-2"><Copy size={15} /> Wireshark filter ready</span>
        <span className="inline-flex items-center gap-2 rounded-full border border-benign/40 bg-surface px-3.5 py-2 text-benign"><CheckCircle size={15} /> Router failover ruled out</span>
      </div>
      <p className="rounded-[14px] border border-neon/35 bg-neon/[0.06] px-5 py-3.5 text-[17px]">
        <span className="font-mono font-bold text-neon">Fix:</span> disconnect 08:00:27:3e:5a:11, then turn on ARP protection.
      </p>
    </div>
  );
}

function YourTurn() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function runCase() {
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
  const stats = [
    ["135/135", "right verdicts, held-out set", "text-neon"], ["0", "false alarms on 55 look-alikes", "text-neon"],
    ["20k", "packets per second", "text-amber"], ["0 B", "sent anywhere", "text-amber"],
  ];
  return (
    <div className="mx-auto flex max-w-[1100px] flex-col items-center gap-[30px] text-center">
      <Eyebrow>06 · Your turn</Eyebrow>
      <h2 className="font-mono text-[clamp(44px,5vw,64px)] font-bold leading-none tracking-[-0.03em] text-white">Your capture next.</h2>
      <p className="text-[18px] text-muted">Runs on your computer. Nothing leaves it. The upload is deleted when the analysis ends.</p>
      <div className="grid w-full gap-px overflow-hidden rounded-[18px] border border-line bg-line sm:grid-cols-2 lg:grid-cols-4">
        {stats.map(([v, label, tone]) => (
          <div key={label} className="bg-surface p-[22px]">
            <p className={`glow-text font-mono text-[38px] font-bold ${tone}`}>{v}</p>
            <p className="mt-1 text-muted">{label}</p>
          </div>
        ))}
      </div>
      <div className="flex flex-wrap justify-center gap-3">
        <a href={href("/app/new")} className="nt-btn nt-primary inline-flex items-center gap-2.5 rounded-xl bg-neon px-6 py-[15px] font-mono text-[16px] font-bold text-on-primary shadow-glow">
          Analyse a capture <span className="nt-arrow">→</span>
        </a>
        <button type="button" onClick={runCase} disabled={busy}
          className="nt-btn nt-ghost inline-flex items-center gap-2.5 rounded-xl border border-line bg-surface px-6 py-[15px] font-mono text-[16px] font-semibold disabled:opacity-60">
          {busy ? "Analysing..." : "Run this case for real"}
        </button>
      </div>
      {error && <p role="alert" className="text-[13px] text-attack">{error}</p>}
      <p className="text-[12px] text-muted">Accuracy measured on labelled captures from our own simulator. Test only networks you own.</p>
    </div>
  );
}
