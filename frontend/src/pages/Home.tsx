import { useEffect, useRef, useState, type DragEvent } from "react";
import { api, ApiError } from "../lib/api";
import { bytes } from "../lib/format";
import { listRecent, type Recent } from "../lib/recent";
import { href, navigate } from "../lib/router";
import type { Sample, ServerConfig } from "../lib/types";
import {
  Activity, ArrowLeft, CheckCircle, ChevronRight, Cpu, FileIcon, Fingerprint, Lock, ShieldAlert, Trash, Upload, WifiOff,
  Wrench, X,
} from "../components/icons";
import { LayerStack, NetworkDiorama } from "../components/Scene3D";
import { Tilt } from "../components/Tilt";
import { TopBar, scrollToSection } from "../components/TopBar";
import { CopyButton } from "../components/ui";

const GROUPS: { key: string; title: string; blurb: string }[] = [
  { key: "attack", title: "Attacks", blurb: "Someone on the network is doing this on purpose." },
  { key: "fault", title: "Faults", blurb: "Something is broken or misconfigured. Nobody is attacking." },
  { key: "mixed", title: "Mixed", blurb: "A fault and an attack in the same capture: both must be told apart." },
  { key: "negative", title: "Look-alikes", blurb: "Looks suspicious, but is normal. NetTriage should explain it, not raise an alarm." },
  { key: "malicious", title: "Hostile files", blurb: "Broken or booby-trapped files that would crash a careless parser." },
];

type Problem = { text: string; refused: boolean };

export function Home() {
  const [config, setConfig] = useState<ServerConfig | null>(null);
  const [samples, setSamples] = useState<Sample[]>([]);
  const [recent] = useState<Recent[]>(listRecent);
  const [error, setError] = useState<Problem | null>(null);
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [group, setGroup] = useState("attack");
  const input = useRef<HTMLInputElement>(null);

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

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setDragging(false);
    pick(e.dataTransfer.files?.[0]);
  }

  const limit = config ? bytes(config.max_upload_bytes) : "500 MB";
  const shown = samples.filter((s) => s.category === group);

  return (
    <div className="flex min-h-full flex-col">
      <TopBar home />

      {/* Hero */}
      <section className="hero-bg relative overflow-hidden text-white">
        <div className="mx-auto grid max-w-[1400px] items-center gap-6 px-4 pb-28 pt-14 sm:px-6 lg:grid-cols-[1.05fr_1fr] lg:pt-20">
          <div>
            <p className="eyebrow">Offline packet-capture diagnosis</p>
            <h1 className="display mt-4 text-[38px] font-semibold leading-[1.08] sm:text-[52px]">
              Is your network broken,<br />or is someone <span className="text-gold">breaking it?</span>
            </h1>
            <p className="mt-5 max-w-xl text-[16px] leading-relaxed text-white/80">
              Drop in a packet capture. NetTriage finds the faults and attacks inside it, tells you which is which and
              how sure it is, explains it in plain language, and shows the exact packets behind every conclusion.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <button type="button" className="btn btn-gold px-5 py-2.5 text-[14px]" onClick={() => scrollToSection("analyse")}>
                <Upload size={16} /> Analyse a capture
              </button>
              <button type="button" className="btn btn-ghost-light px-5 py-2.5 text-[14px]" onClick={() => scrollToSection("samples")}>
                Try a sample <ChevronRight size={15} />
              </button>
            </div>
            <ul className="mt-9 flex flex-wrap gap-x-6 gap-y-2 text-[13px] text-white/75">
              <li className="flex items-center gap-2"><WifiOff size={15} className="text-gold" /> Works fully offline</li>
              <li className="flex items-center gap-2"><Trash size={15} className="text-gold" /> Upload deleted after analysis</li>
              <li className="flex items-center gap-2"><Activity size={15} className="text-gold" /> 14 kinds of problem, explained</li>
            </ul>
          </div>
          <NetworkDiorama />
        </div>
      </section>

      <main className="flex-1">
        {/* Upload */}
        <section id="analyse" className="relative z-10 mx-auto -mt-20 max-w-[1100px] scroll-mt-24 px-4 sm:px-6">
          <div className="card grid gap-0 overflow-hidden shadow-lift md:grid-cols-[1.4fr_1fr]">
            <div
              onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onDrop={onDrop}
              className={`m-3 flex flex-col items-center justify-center gap-4 rounded-xl border-2 border-dashed px-6 py-10 text-center
                transition-colors ${dragging ? "border-gold bg-gold/10" : "border-line"}`}>
              <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-navy text-gold shadow-lift">
                <Upload size={24} />
              </div>
              <div>
                <p className="display text-[20px] font-semibold">Drop a capture file here</p>
                <p className="mt-1 text-muted">.pcap, .pcapng or .cap, up to {limit}. Saved by Wireshark or tcpdump.</p>
              </div>
              <button type="button" className="btn btn-primary px-5" disabled={busy} onClick={() => input.current?.click()}>
                <FileIcon size={15} /> {busy ? "Starting..." : "Choose a file"}
              </button>
              <input ref={input} type="file" accept=".pcap,.pcapng,.cap" className="hidden"
                onChange={(e) => pick(e.target.files?.[0])} />
              <button type="button" className="link text-[13px]" onClick={() => scrollToSection("capture")}>
                Don't have a capture? Here's how to make one
              </button>
            </div>
            <div className="border-t border-line bg-raised/60 p-6 md:border-l md:border-t-0">
              <p className="label">What happens to your file</p>
              <ol className="mt-4 space-y-4">
                {[
                  { Icon: Fingerprint, t: "Checked first", d: "Its signature is checked before a single packet is read. Anything that isn't a capture is refused." },
                  { Icon: Cpu, t: "Analysed in isolation", d: "A separate, time-limited process reads it. Damaged packets are skipped, never fatal." },
                  { Icon: Trash, t: "Deleted straight after", d: "The upload is removed the moment analysis ends. Only the report is kept, in memory." },
                ].map(({ Icon, t, d }) => (
                  <li key={t} className="flex gap-3">
                    <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-navy/10 text-primary dark:bg-white/10">
                      <Icon size={16} />
                    </span>
                    <span>
                      <span className="block font-semibold">{t}</span>
                      <span className="text-[13px] leading-relaxed text-muted">{d}</span>
                    </span>
                  </li>
                ))}
              </ol>
            </div>
          </div>

          {recent.length > 0 && (
            <div className="mt-6">
              <p className="label mb-2">Your recent analyses</p>
              <div className="flex flex-wrap gap-2">
                {recent.map((r) => (
                  <a key={r.id} href={href(`/a/${r.id}`)} className="card flex items-center gap-3 px-3.5 py-2 transition-colors hover:border-primary/40">
                    <FileIcon size={15} className="text-muted" />
                    <span className="max-w-[220px] truncate font-medium">{r.name}</span>
                    <span className="text-[12px] text-muted">
                      {r.attacks ? <span className="font-semibold text-attack">{r.attacks} attack{r.attacks > 1 ? "s" : ""}</span>
                        : r.faults ? <span className="font-semibold text-fault">{r.faults} fault{r.faults > 1 ? "s" : ""}</span>
                          : <span className="font-semibold text-benign">clean</span>}
                    </span>
                  </a>
                ))}
              </div>
            </div>
          )}
        </section>

        {/* How it works */}
        <section id="how" className="mx-auto max-w-[1200px] scroll-mt-20 px-4 py-24 sm:px-6">
          <div className="grid items-center gap-12 lg:grid-cols-[1fr_1fr]">
            <div>
              <p className="eyebrow">How it works</p>
              <h2 className="display mt-3 text-[34px] font-semibold leading-tight text-navy dark:text-white">
                Faults are consistent. Attacks have to lie.
              </h2>
              <p className="mt-4 text-[15px] leading-relaxed text-muted">
                A broken network still tells the truth: everything agrees, something just doesn't work. An attacker has
                to deceive someone, and that leaves contradictions between the layers of the traffic. NetTriage looks for
                both, weighs every competing explanation, and tells you how sure it is.
              </p>
              <ol className="mt-8 space-y-5">
                {[
                  ["Read every packet safely", "Our own decoders read the capture byte by byte, with every length field checked."],
                  ["Weigh competing explanations", "Each issue is scored as an attack, a fault or something normal, using published detection methods such as the TRW port-scan test and the Hold-On DNS check."],
                  ["Explain it and point to proof", "You get a plain-language verdict, what to do about it, and the exact packets, with a ready-made Wireshark filter."],
                ].map(([t, d], i) => (
                  <li key={t} className="flex gap-4">
                    <span className="display flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-gold text-[16px] font-semibold text-navy shadow-gold">
                      {i + 1}
                    </span>
                    <span>
                      <span className="block text-[15px] font-semibold">{t}</span>
                      <span className="text-[13.5px] leading-relaxed text-muted">{d}</span>
                    </span>
                  </li>
                ))}
              </ol>
            </div>
            <div className="hero-bg rounded-3xl p-6 shadow-lift">
              <LayerStack />
              <p className="px-4 pb-2 text-center text-[13px] text-white/70">
                The layers NetTriage cross-checks. A DHCP server naming itself the gateway, or a DNS reply that arrives
                before the server could have sent it, is the kind of contradiction that gives an attack away.
              </p>
            </div>
          </div>
        </section>

        {/* What it finds */}
        <section id="detects" className="scroll-mt-20 border-y border-line bg-surface/60 py-24">
          <div className="mx-auto max-w-[1200px] px-4 sm:px-6">
            <p className="eyebrow">What it finds</p>
            <h2 className="display mt-3 max-w-2xl text-[34px] font-semibold leading-tight text-navy dark:text-white">
              Fourteen kinds of problem, and the look-alikes that aren't problems at all
            </h2>
            <div className="mt-10 grid gap-5 md:grid-cols-3">
              <DetectColumn Icon={Wrench} tone="text-fault" title="Faults it diagnoses" items={[
                "Packet loss, located to a server, a PC's link or the uplink",
                "Duplicate IP addresses",
                "DNS servers failing, timing out or slow",
                "Services refusing connections, hosts not answering",
                "Internet outages, unusually slow servers",
                "DHCP servers down or misplugged home routers",
              ]} />
              <DetectColumn Icon={ShieldAlert} tone="text-attack" title="Attacks it detects" items={[
                "ARP spoofing and man-in-the-middle, with proof of relaying",
                "Port scans, including slow and stealth (Xmas, FIN, NULL) scans",
                "Forged DNS answers and poisoning floods",
                "Rogue DHCP servers that hijack the gateway",
                "Network sweeps",
              ]} />
              <DetectColumn Icon={CheckCircle} tone="text-benign" title="Look-alikes it rules out" items={[
                "Router failover (VRRP/HSRP), not ARP spoofing",
                "A replaced network card, not an impostor",
                "Ad blockers and CDN rotation, not DNS hijacking",
                "A busy PC, not a port scanner",
                "A one-directional capture, not a dead network",
              ]} />
            </div>
          </div>
        </section>

        {/* Samples */}
        {samples.length > 0 && (
          <section id="samples" className="mx-auto max-w-[1200px] scroll-mt-20 px-4 py-24 sm:px-6">
            <div className="flex flex-wrap items-end justify-between gap-4">
              <div>
                <p className="eyebrow">Try it now</p>
                <h2 className="display mt-3 text-[34px] font-semibold leading-tight text-navy dark:text-white">Sample captures</h2>
                <p className="mt-2 max-w-xl text-muted">Labelled, simulated captures of a six-PC office. Click one to see a full report.</p>
              </div>
              <div role="tablist" className="flex flex-wrap gap-1 rounded-xl border border-line bg-surface p-1 shadow-card">
                {GROUPS.filter((g) => samples.some((s) => s.category === g.key)).map((g) => (
                  <button key={g.key} role="tab" aria-selected={group === g.key} type="button" onClick={() => setGroup(g.key)}
                    className={`rounded-lg px-3 py-1.5 text-[13px] font-semibold transition-colors ${group === g.key
                      ? "bg-navy text-white" : "text-muted hover:text-ink"}`}>
                    {g.title}
                    <span className={`ml-1.5 ${group === g.key ? "text-gold" : "text-muted"}`}>
                      {samples.filter((s) => s.category === g.key).length}
                    </span>
                  </button>
                ))}
              </div>
            </div>
            <p className="mt-5 text-[14px] text-muted">{GROUPS.find((g) => g.key === group)?.blurb}</p>
            <div className="mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {shown.map((s) => (
                <Tilt key={s.name} className="rounded-2xl">
                  <button type="button" disabled={busy} onClick={() => start(() => api.analyseSample(s.name))}
                    className="card flex h-full w-full flex-col gap-2 p-5 text-left transition-colors hover:border-gold/60">
                    <span className="flex items-start justify-between gap-2">
                      <span className="text-[15px] font-semibold">{s.title}</span>
                      <span className="shrink-0 rounded-md bg-raised px-1.5 py-0.5 text-[11.5px] text-muted">{bytes(s.size)}</span>
                    </span>
                    <span className="line-clamp-3 text-[13px] leading-relaxed text-muted">{s.description}</span>
                    <span className="mt-auto flex items-center justify-between pt-2">
                      <span className="mono text-[11.5px] text-muted/80">{s.name}</span>
                      <span className="flex items-center gap-1 text-[12.5px] font-semibold text-primary">Analyse <ChevronRight size={14} /></span>
                    </span>
                  </button>
                </Tilt>
              ))}
            </div>
          </section>
        )}

        {/* Security */}
        <section id="security" className="hero-bg scroll-mt-16 py-24 text-white">
          <div className="mx-auto max-w-[1200px] px-4 sm:px-6">
            <p className="eyebrow">Built to be handed hostile files</p>
            <h2 className="display mt-3 max-w-2xl text-[34px] font-semibold leading-tight">
              Your capture is sensitive. NetTriage treats it that way.
            </h2>
            <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {[
                { Icon: WifiOff, t: "Fully offline", d: "No cloud, no telemetry, no outbound connections. A test fails the build if any code tries to open one." },
                { Icon: Fingerprint, t: "Checked before parsing", d: "A renamed .exe or zip is refused from its first bytes, with what it really is." },
                { Icon: Lock, t: "Every length checked", d: "Our own decoders read every field through one bounds-checked reader. Pointer loops and 4 GB claims are refused." },
                { Icon: Cpu, t: "Isolated and time-limited", d: "Each analysis runs in its own process and is killed if it runs too long." },
                { Icon: ShieldAlert, t: "Packet text made harmless", d: "Hostnames like <script> are escaped and shown as text. Terminal escapes and direction overrides are neutralised." },
                { Icon: Trash, t: "Nothing kept", d: "Uploads are deleted after analysis; reports live in memory for an hour, or until you delete them." },
              ].map(({ Icon, t, d }) => (
                <Tilt key={t} className="rounded-2xl" max={5}>
                  <div className="h-full rounded-2xl border border-white/15 bg-white/[0.04] p-5">
                    <Icon size={20} className="text-gold" />
                    <p className="mt-3 font-semibold">{t}</p>
                    <p className="mt-1 text-[13px] leading-relaxed text-white/70">{d}</p>
                  </div>
                </Tilt>
              ))}
            </div>
            <button type="button" className="btn btn-gold mt-8" onClick={() => { setGroup("malicious"); scrollToSection("samples"); }}>
              See it handle hostile files <ChevronRight size={15} />
            </button>
          </div>
        </section>

        <CaptureGuide />
      </main>

      <footer className="border-t border-line bg-surface py-8">
        <div className="mx-auto flex max-w-[1200px] flex-wrap items-center justify-between gap-3 px-4 text-[12.5px] text-muted sm:px-6">
          <span className="display text-[15px] font-semibold text-navy dark:text-white">NetTriage <span className="text-gold">{config?.version ?? ""}</span></span>
          <span>Runs on this computer · results kept for {config?.retention_minutes ?? 60} minutes · test only networks you own</span>
        </div>
      </footer>

      {error && (
        <div role="alert" className={`fixed inset-x-0 bottom-6 z-40 mx-auto flex w-[min(640px,calc(100%-2rem))] items-start gap-3
          rounded-2xl border bg-surface p-4 shadow-lift ${error.refused ? "border-benign/50" : "border-attack/50"}`}>
          <ShieldAlert size={20} className={`mt-0.5 shrink-0 ${error.refused ? "text-benign" : "text-attack"}`} />
          <div className="flex-1">
            <p className="font-semibold">{error.refused ? "File refused" : "Could not start the analysis"}</p>
            <p className="mt-0.5 text-[13.5px]">{error.text}</p>
            {error.refused && <p className="mt-1 text-[12.5px] text-muted">Nothing was parsed, and nothing was kept.</p>}
          </div>
          <button type="button" className="btn px-2" onClick={() => setError(null)} aria-label="Dismiss"><X size={14} /></button>
        </div>
      )}
    </div>
  );
}

function DetectColumn({ Icon, tone, title, items }: { Icon: typeof Wrench; tone: string; title: string; items: string[] }) {
  return (
    <Tilt className="rounded-2xl" max={4}>
      <div className="card h-full p-6">
        <span className={`flex h-10 w-10 items-center justify-center rounded-xl bg-raised ${tone}`}><Icon size={20} /></span>
        <p className="mt-4 text-[16px] font-semibold">{title}</p>
        <ul className="mt-3 space-y-2">
          {items.map((i) => (
            <li key={i} className="flex gap-2 text-[13.5px] leading-relaxed">
              <span className="mt-[7px] h-1.5 w-1.5 shrink-0 rounded-full bg-gold" />
              {i}
            </li>
          ))}
        </ul>
      </div>
    </Tilt>
  );
}

const GUIDES = {
  windows: {
    label: "Windows",
    steps: [
      "Install Wireshark from wireshark.org (it includes the Npcap capture driver).",
      "Open Wireshark, double-click the network you use (Wi-Fi or Ethernet), and use the network as usual while the problem happens.",
      "Click the red square to stop, then File > Save As and keep the .pcapng format.",
    ],
    command: "",
  },
  mac: {
    label: "macOS",
    steps: [
      "Open Terminal. en0 is usually Wi-Fi; check with `networksetup -listallhardwareports`.",
      "Run the command below, reproduce the problem, then press Ctrl+C.",
    ],
    command: "sudo tcpdump -i en0 -w capture.pcap",
  },
  linux: {
    label: "Linux",
    steps: [
      "Find your interface name with `ip link` (for example eth0 or wlp2s0).",
      "Run the command below, reproduce the problem, then press Ctrl+C.",
    ],
    command: "sudo tcpdump -i eth0 -w capture.pcap",
  },
} as const;

function CaptureGuide() {
  const [os, setOs] = useState<keyof typeof GUIDES>("windows");
  const g = GUIDES[os];
  return (
    <section id="capture" className="mx-auto max-w-[1200px] scroll-mt-20 px-4 py-24 sm:px-6">
      <div className="grid gap-10 lg:grid-cols-[1fr_1.2fr]">
        <div>
          <p className="eyebrow">Make a capture</p>
          <h2 className="display mt-3 text-[34px] font-semibold leading-tight text-navy dark:text-white">
            No capture yet? Two minutes is enough.
          </h2>
          <p className="mt-4 text-[15px] leading-relaxed text-muted">
            Record while the problem is happening. A minute or two of traffic is usually plenty. To see the whole
            office instead of one PC, capture on a switch mirror port that copies <span className="font-semibold text-ink">both directions</span>.
          </p>
          <p className="mt-4 flex items-start gap-2 rounded-xl border border-gold/50 bg-gold/10 p-3 text-[13px] leading-relaxed">
            <Lock size={16} className="mt-0.5 shrink-0 text-primary" />
            Only capture networks you own or have permission to monitor. Captures can contain private information,
            which is why NetTriage never sends them anywhere.
          </p>
        </div>
        <div className="card overflow-hidden">
          <div className="flex border-b border-line bg-raised/60" role="tablist">
            {(Object.keys(GUIDES) as (keyof typeof GUIDES)[]).map((k) => (
              <button key={k} type="button" role="tab" aria-selected={os === k} onClick={() => setOs(k)}
                className={`flex-1 px-4 py-3 text-[13px] font-semibold transition-colors ${os === k
                  ? "border-b-2 border-gold bg-surface text-ink" : "text-muted hover:text-ink"}`}>
                {GUIDES[k].label}
              </button>
            ))}
          </div>
          <div className="p-6">
            <ol className="space-y-3">
              {g.steps.map((s, i) => (
                <li key={s} className="flex gap-3 text-[14px] leading-relaxed">
                  <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-navy text-[12px] font-semibold text-white">{i + 1}</span>
                  {s}
                </li>
              ))}
            </ol>
            {g.command && (
              <div className="mt-5 flex items-center justify-between gap-3 rounded-xl bg-navy px-4 py-3">
                <code className="mono text-[13px] text-[#f0d88a]">{g.command}</code>
                <CopyButton text={g.command} label="Copy" />
              </div>
            )}
            <button type="button" className="btn btn-gold mt-6" onClick={() => scrollToSection("analyse")}>
              <ArrowLeft size={15} className="rotate-90" /> I have a capture: analyse it
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}
