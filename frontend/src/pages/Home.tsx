import { useEffect, useRef, useState, type DragEvent } from "react";
import { api, ApiError } from "../lib/api";
import { bytes } from "../lib/format";
import { useCycle } from "../lib/live";
import { listRecent, type Recent } from "../lib/recent";
import { href, navigate } from "../lib/router";
import type { Sample, ServerConfig } from "../lib/types";
import { CheckCircle, Cpu, Fingerprint, Lock, ShieldAlert, Trash, WifiOff, Wrench, X } from "../components/icons";
import { CrtLog, KeyButton, Prompt, RadarDish, Ticker, type LogLine, type Tick } from "../components/Console";
import { Tilt } from "../components/Tilt";
import { TopBar, scrollToSection } from "../components/TopBar";
import { CopyButton } from "../components/ui";

// Real output: `nettriage analyze samples/scenarios/lossy_link_plus_scan.pcap`, shortened to fit.
const LOG: LogLine[] = [
  { t: "$ nettriage analyze lossy_link_plus_scan.pcap", c: "text-neon" },
  { t: "  2,669 packets · 59.6 s · 9 devices · 0.14 s", c: "text-amber/60" },
  { t: "[ATTACK 100%] 192.168.1.66 is scanning 192.168.1.50", c: "text-attack" },
  { t: "[FAULT  100%] Packet loss on the path to 151.101.1.69", c: "text-amber" },
  { t: "  evidence: frames 199, 956, 961, 963 ...", c: "text-amber/60" },
  { t: "  wireshark: ip.src == 192.168.1.66", c: "text-amber/60" },
];
const LOG_TEXT = LOG.map((l) => l.t);

const TICKS: Tick[] = [
  { t: "ARP SPOOFING", v: "ATTACK", c: "text-attack" },
  { t: "DNS TIMEOUTS", v: "FAULT", c: "text-fault" },
  { t: "ROUTER FAILOVER", v: "RULED OUT", c: "text-benign" },
  { t: "PORT SCAN", v: "ATTACK", c: "text-attack" },
  { t: "PACKET LOSS", v: "FAULT", c: "text-fault" },
  { t: "AD BLOCKER", v: "RULED OUT", c: "text-benign" },
  { t: "ROGUE DHCP", v: "ATTACK", c: "text-attack" },
  { t: "MTU BLACK HOLE", v: "FAULT", c: "text-fault" },
  { t: "SWAPPED NIC", v: "RULED OUT", c: "text-benign" },
  { t: "FORGED DNS", v: "ATTACK", c: "text-attack" },
  { t: "DUPLICATE IP", v: "FAULT", c: "text-fault" },
];

const GROUPS = [
  { key: "attack", title: "Attacks", hint: "Done on purpose", bar: "bg-attack" },
  { key: "fault", title: "Faults", hint: "Broken, nobody attacking", bar: "bg-fault" },
  { key: "mixed", title: "Mixed", hint: "Both, told apart", bar: "bg-review" },
  { key: "negative", title: "Look-alikes", hint: "Looks bad, is normal", bar: "bg-benign" },
  { key: "malicious", title: "Hostile files", hint: "Booby-trapped captures", bar: "bg-attack" },
];

const CATCHES = [
  { Icon: ShieldAlert, title: "Attacks", tone: "text-attack", border: "hover:border-attack/60",
    items: ["ARP spoofing / MITM", "Port scans, even stealthy", "Forged DNS answers", "Rogue DHCP servers", "Network sweeps"] },
  { Icon: Wrench, title: "Faults", tone: "text-fault", border: "hover:border-fault/60",
    items: ["Packet loss, pinpointed", "Duplicate IPs", "DNS down or slow", "Refused or dead services", "Outages, MTU black holes", "DHCP failures"] },
  { Icon: CheckCircle, title: "Ruled out", tone: "text-benign", border: "hover:border-benign/60",
    items: ["Router failover", "Swapped network card", "Ad blockers, CDNs", "Busy PCs", "One-way captures"] },
];

const CHECKS = [
  { Icon: WifiOff, t: "Offline", d: "No outbound connections" },
  { Icon: Fingerprint, t: "Signature check", d: "Renamed .exe refused" },
  { Icon: Lock, t: "Bounded parser", d: "Every length checked" },
  { Icon: Cpu, t: "Isolated worker", d: "Killed if too slow" },
  { Icon: ShieldAlert, t: "Escaped output", d: "<script> shown as text" },
  { Icon: Trash, t: "Nothing kept", d: "Upload deleted after" },
];

type Problem = { text: string; refused: boolean };

export function Home() {
  const [config, setConfig] = useState<ServerConfig | null>(null);
  const [samples, setSamples] = useState<Sample[]>([]);
  const [recent] = useState<Recent[]>(listRecent);
  const [error, setError] = useState<Problem | null>(null);
  const [busy, setBusy] = useState(false);
  const [over, setOver] = useState(false);
  const [group, setGroup] = useState("attack");
  const input = useRef<HTMLInputElement>(null);
  const check = useCycle(CHECKS.length + 4, 600);

  useEffect(() => {
    api.config().then(setConfig).catch(() => setConfig(null));
    api.samples().then(setSamples).catch(() => setSamples([]));
  }, []);

  async function start(run: () => Promise<{ id: string }>) {
    setBusy(true);
    setError(null);
    try {
      const { id } = await run();
      navigate(`/a/${id}`);
      window.scrollTo({ top: 0 });
    } catch (e) {
      setError(e instanceof ApiError ? { text: e.message, refused: e.status === 413 || e.status === 415 }
        : { text: "Something went wrong.", refused: false });
      setBusy(false);
    }
  }

  function pick(file: File | undefined) {
    if (!file) return;
    if (config && file.size > config.max_upload_bytes) {
      setError({ text: `That file is ${bytes(file.size)}; the limit is ${bytes(config.max_upload_bytes)}.`, refused: true });
      return;
    }
    start(() => api.upload(file));
  }

  // Featured demo captures for the "S" key: one of each kind of verdict.
  const featured = ["mitm_dns_combo.pcap", "lossy_link_plus_scan.pcap", "dns_spoof_race.pcap", "port_scan_syn.pcap", "dns_timeout.pcap"]
    .filter((n) => samples.some((s) => s.name === n));
  const randomSample = () => {
    if (busy || !featured.length) return;
    const name = featured[Math.floor(Math.random() * featured.length)];
    start(() => api.analyseSample(name));
  };

  // U opens the file picker, S runs a sample. Ignored while typing or with modifier keys.
  const keys = useRef({ pick: () => input.current?.click(), randomSample });
  keys.current = { pick: () => input.current?.click(), randomSample };
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      if (e.ctrlKey || e.metaKey || e.altKey || e.repeat || t?.closest("input, textarea, [contenteditable]")) return;
      if (e.key.toLowerCase() === "u") keys.current.pick();
      if (e.key.toLowerCase() === "s") keys.current.randomSample();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const dropProps = {
    onDragOver: (e: DragEvent) => { e.preventDefault(); setOver(true); },
    onDragLeave: () => setOver(false),
    onDrop: (e: DragEvent) => { e.preventDefault(); setOver(false); pick(e.dataTransfer.files?.[0]); },
  };
  const limit = config ? bytes(config.max_upload_bytes) : "500 MB";
  const shown = samples.filter((s) => s.category === group);
  const activeGroup = GROUPS.find((g) => g.key === group);

  return (
    <div className="flex min-h-full flex-col">
      <TopBar home />

      {/* Hero: drop anywhere in here */}
      <section id="analyse" {...dropProps} className={`console-bg relative scroll-mt-14 overflow-hidden transition-colors ${over ? "bg-neon/5" : ""}`}>
        <div className="mx-auto grid max-w-[1320px] items-center gap-x-10 gap-y-8 px-4 pb-12 pt-10 sm:px-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] lg:pt-14">
          <div className="min-w-0">
            <h1 className="font-mono text-[clamp(40px,5.8vw,76px)] font-bold uppercase leading-[0.95] tracking-tight text-white">
              Broken<br />or <span className="glow-text text-attack">breached?</span>
            </h1>
            <p className="eyebrow mt-4">Faults · Attacks · Proof</p>

            <div className="mt-8 grid max-w-xl gap-3 sm:grid-cols-2">
              <KeyButton k="U" title={busy ? "running..." : "upload"} sub={`or drop it · max ${limit}`}
                onClick={() => input.current?.click()} disabled={busy} />
              <KeyButton k="S" title="sample" sub="random demo capture" onClick={randomSample} disabled={busy || !featured.length} />
            </div>
            <input ref={input} type="file" accept=".pcap,.pcapng,.cap" className="hidden" onChange={(e) => pick(e.target.files?.[0])} />

            {recent.length > 0 && (
              <div className="mt-6 max-w-xl font-mono text-[12.5px]">
                <p className="label mb-1.5">Recent</p>
                {recent.slice(0, 3).map((r) => (
                  <a key={r.id} href={href(`/a/${r.id}`)} className="group flex items-center gap-3 py-0.5 hover:text-neon">
                    <span className="text-muted group-hover:text-neon">↻</span>
                    <span className="min-w-0 flex-1 truncate">{r.name}</span>
                    {r.attacks ? <span className="text-attack">{r.attacks} attack{r.attacks > 1 ? "s" : ""}</span>
                      : r.faults ? <span className="text-fault">{r.faults} fault{r.faults > 1 ? "s" : ""}</span>
                        : <span className="text-benign">clean</span>}
                  </a>
                ))}
              </div>
            )}

            <CrtLog lines={LOG} texts={LOG_TEXT} className="mt-8 max-w-xl" />
          </div>

          <div className="flex min-w-0 flex-col items-center">
            <button type="button" onClick={() => input.current?.click()} disabled={busy} aria-label="Drop or choose a capture file"
              className="w-[min(540px,86vw)] rounded-full focus:outline-none focus-visible:ring-2 focus-visible:ring-neon/70">
              <RadarDish active={over} className="w-full">
                <span className="absolute inset-x-0 bottom-[16%] text-center font-mono text-[13px] tracking-[0.3em] text-neon glow-text">
                  {busy ? "ANALYSING..." : over ? "RELEASE TO SCAN" : "DROP .PCAP HERE"}
                </span>
              </RadarDish>
            </button>
            <p className="-mt-2 font-mono text-[11.5px] tracking-[0.18em] text-muted">CHECKED · ISOLATED · DELETED AFTER</p>
          </div>
        </div>
      </section>

      <Ticker items={TICKS} label="DETECTS" />

      <main className="flex-1">
        {/* Samples */}
        {samples.length > 0 && (
          <section id="samples" className="mx-auto max-w-[1320px] scroll-mt-16 px-4 py-20 sm:px-6">
            <Prompt right={
              <div role="tablist" className="flex flex-wrap gap-1 rounded-lg border border-line bg-surface p-1 font-mono">
                {GROUPS.filter((g) => samples.some((s) => s.category === g.key)).map((g) => (
                  <button key={g.key} role="tab" aria-selected={group === g.key} type="button" onClick={() => setGroup(g.key)}
                    className={`rounded px-3 py-1.5 text-[12px] font-semibold uppercase tracking-[0.08em] transition-colors ${group === g.key
                      ? "bg-neon/15 text-neon" : "text-muted hover:text-ink"}`}>
                    {g.title} <span className="opacity-60">{samples.filter((s) => s.category === g.key).length}</span>
                  </button>
                ))}
              </div>
            }>samples</Prompt>
            <p className="mt-3 font-mono text-[13px] text-muted">{activeGroup?.hint} · click to run</p>
            <div className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
              {shown.map((s) => (
                <Tilt key={s.name} className="rounded-xl" max={6}>
                  <button type="button" disabled={busy} onClick={() => start(() => api.analyseSample(s.name))} title={s.description}
                    className="card group relative flex h-full w-full flex-col gap-3 overflow-hidden p-4 pl-5 text-left transition-colors hover:border-neon/50">
                    <span className={`absolute inset-y-0 left-0 w-1 ${activeGroup?.bar ?? "bg-neon"}`} />
                    <span className="text-[14.5px] font-semibold leading-snug text-white">{s.title}</span>
                    <span className="mt-auto flex items-center justify-between gap-2 font-mono text-[11.5px]">
                      <span className="truncate text-muted">{s.name}</span>
                      <span className="shrink-0 font-bold tracking-[0.1em] text-neon opacity-70 transition-opacity group-hover:opacity-100">RUN ▸</span>
                    </span>
                  </button>
                </Tilt>
              ))}
            </div>
          </section>
        )}

        {/* What it catches */}
        <section id="detects" className="scroll-mt-16 border-y border-line bg-surface/40 py-20">
          <div className="mx-auto max-w-[1320px] px-4 sm:px-6">
            <Prompt>catches</Prompt>
            <div className="mt-8 grid gap-4 md:grid-cols-3">
              {CATCHES.map(({ Icon, title, tone, border, items }) => (
                <Tilt key={title} className="rounded-xl" max={4}>
                  <div className={`card h-full p-5 transition-colors ${border}`}>
                    <p className={`flex items-center gap-2 font-mono text-[13px] font-bold uppercase tracking-[0.2em] ${tone}`}>
                      <Icon size={17} /> {title}
                    </p>
                    <ul className="mt-4 space-y-2 font-mono text-[13px]">
                      {items.map((i) => (
                        <li key={i} className="flex gap-2.5"><span className={tone}>▸</span>{i}</li>
                      ))}
                    </ul>
                  </div>
                </Tilt>
              ))}
            </div>
          </div>
        </section>

        {/* Security */}
        <section id="security" className="mx-auto max-w-[1320px] scroll-mt-16 px-4 py-20 sm:px-6">
          <Prompt right={
            <button type="button" className="btn" onClick={() => { setGroup("malicious"); scrollToSection("samples"); }}>
              Feed it a hostile file ▸
            </button>
          }>security</Prompt>
          <div className="mt-8 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {CHECKS.map(({ Icon, t, d }, i) => {
              const ok = i < check;
              return (
                <Tilt key={t} className="rounded-xl" max={5}>
                  <div className={`card flex h-full items-center gap-4 p-4 transition-colors ${ok ? "border-neon/40" : ""}`}>
                    <Icon size={20} className={ok ? "text-neon" : "text-muted"} />
                    <span className="min-w-0 flex-1">
                      <span className="block font-mono text-[14px] font-bold text-white">{t}</span>
                      <span className="block truncate font-mono text-[12px] text-muted">{d}</span>
                    </span>
                    <span className={`shrink-0 font-mono text-[12px] font-bold ${ok ? "text-neon glow-text" : "text-muted/50"}`}>
                      {ok ? "[ OK ]" : "[ .. ]"}
                    </span>
                  </div>
                </Tilt>
              );
            })}
          </div>
        </section>

        <CaptureGuide />
      </main>

      <footer className="border-t border-line py-6 font-mono text-[11.5px] tracking-[0.08em] text-muted">
        <div className="mx-auto flex max-w-[1320px] flex-wrap items-center justify-between gap-3 px-4 sm:px-6">
          <span className="font-bold tracking-[0.22em] text-neon">NETTRIAGE {config?.version ?? ""}</span>
          <span>runs on this computer · reports kept {config?.retention_minutes ?? 60} min · test only networks you own ·{" "}
            <a href={href("/designs")} className="hover:text-neon">design concepts</a></span>
        </div>
      </footer>

      {error && (
        <div role="alert" className={`fixed inset-x-0 bottom-6 z-40 mx-auto flex w-[min(620px,calc(100%-2rem))] items-start gap-3
          rounded-lg border bg-surface p-4 font-mono shadow-lift ${error.refused ? "border-neon/50" : "border-attack/60"}`}>
          <ShieldAlert size={18} className={`mt-0.5 shrink-0 ${error.refused ? "text-neon" : "text-attack"}`} />
          <div className="min-w-0 flex-1">
            <p className={`text-[13px] font-bold uppercase tracking-[0.12em] ${error.refused ? "text-neon" : "text-attack"}`}>
              {error.refused ? "File refused" : "Could not start"}
            </p>
            <p className="mt-1 text-[13px]">{error.text}</p>
            {error.refused && <p className="mt-1 text-[12px] text-muted">Nothing parsed. Nothing kept.</p>}
          </div>
          <button type="button" className="btn px-2" onClick={() => setError(null)} aria-label="Dismiss"><X size={14} /></button>
        </div>
      )}
    </div>
  );
}

const GUIDES = {
  windows: { label: "Windows", steps: ["Install Wireshark", "Pick your network, reproduce the problem", "Stop, then save as .pcapng"], command: "" },
  mac: { label: "macOS", steps: ["Run this, reproduce the problem, press Ctrl+C"], command: "sudo tcpdump -i en0 -w capture.pcap" },
  linux: { label: "Linux", steps: ["Find your interface with ip link", "Run this, reproduce the problem, press Ctrl+C"],
    command: "sudo tcpdump -i eth0 -w capture.pcap" },
} as const;

function CaptureGuide() {
  const [os, setOs] = useState<keyof typeof GUIDES>("windows");
  const g = GUIDES[os];
  return (
    <section id="capture" className="scroll-mt-16 border-t border-line bg-surface/40 py-20">
      <div className="mx-auto grid max-w-[1320px] gap-8 px-4 sm:px-6 lg:grid-cols-[1fr_1.3fr] lg:items-center">
        <div>
          <Prompt>no capture?</Prompt>
          <p className="mt-3 font-mono text-[13px] text-muted">Two minutes of traffic is enough.</p>
          <p className="mt-4 inline-flex items-center gap-2 rounded border border-amber/40 bg-amber/5 px-3 py-1.5 font-mono text-[12px] text-amber">
            <Lock size={14} /> Only capture networks you own
          </p>
        </div>
        <div className="card overflow-hidden font-mono">
          <div className="flex border-b border-line" role="tablist">
            {(Object.keys(GUIDES) as (keyof typeof GUIDES)[]).map((k) => (
              <button key={k} type="button" role="tab" aria-selected={os === k} onClick={() => setOs(k)}
                className={`flex-1 px-4 py-2.5 text-[12px] font-semibold uppercase tracking-[0.12em] transition-colors ${os === k
                  ? "border-b-2 border-neon text-neon" : "text-muted hover:text-ink"}`}>
                {GUIDES[k].label}
              </button>
            ))}
          </div>
          <div className="p-5">
            <ol className="space-y-2 text-[13px]">
              {g.steps.map((s, i) => (
                <li key={s} className="flex gap-3"><span className="text-neon">{i + 1}.</span>{s}</li>
              ))}
            </ol>
            {g.command && (
              <div className="mt-4 flex items-center justify-between gap-3 rounded-lg border border-line bg-bg px-4 py-2.5">
                <code className="truncate text-[13px] text-amber"><span className="text-neon">$</span> {g.command}</code>
                <CopyButton text={g.command} label="Copy" />
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
