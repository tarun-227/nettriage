// The analysis result, written for people who are not packet experts: the verdict in one sentence,
// what to do, the findings in plain words, and the technical detail tucked into tabs.
import { useEffect, useRef, useState, type ReactNode } from "react";
import { api } from "../lib/api";
import { firstSentence, rootFinding, sortFindings } from "../lib/findings";
import { bytes, duration, num, offset, pct } from "../lib/format";
import { useTitle } from "../lib/live";
import { addRecent, forgetRecent } from "../lib/recent";
import { href, navigate } from "../lib/router";
import type { Finding, Job, Report, Verdict } from "../lib/types";
import { BlastRadius } from "../components/BlastRadius";
import { RadarDish } from "../components/Console";
import { ProofPackDialog } from "../components/ProofPack";
import { Bars, CheckCircle, ChevronDown, Download, FileIcon, Fingerprint, Info, List, Plus, Trash, Wrench } from "../components/icons";
import { CopyButton, EntityChip, SeverityBadge, VerdictChip } from "../components/ui";
import { FindingDetail } from "./FindingDetail";
import { IntegrityTab } from "./Integrity";
import { TimelineTab } from "./Timeline";

export function ReportView({ job, report, rest }: { job: Job; report: Report; rest: string[] }) {
  const attacks = report.findings.filter((f) => f.verdict === "attack").length;
  const faults = report.findings.filter((f) => f.verdict === "fault").length;
  useTitle(`${report.capture.file_name} · ${attacks ? plural(attacks, "attack") : faults ? plural(faults, "fault") : "clean"} · NetTriage`);
  useEffect(() => {
    addRecent({
      id: job.id, name: report.capture.file_name, at: Date.now(), packets: report.ingest.packets_total, size: job.size,
      attacks: report.findings.filter((f) => f.verdict === "attack").length,
      faults: report.findings.filter((f) => f.verdict === "fault").length,
    });
  }, [job.id, job.size, report]);

  const detail = rest[0] === "findings" && rest[1]
    ? [...report.findings, ...report.ruled_out].find((f) => f.id === rest[1]) : undefined;
  return (
    <div className="min-h-full bg-bg">
      <ReportHeader job={job} report={report} />
      {detail ? (
        <main className="mx-auto max-w-[1120px] px-4 pb-20 pt-6 sm:px-6">
          <a href={href(`/a/${job.id}`)} className="nt-nav mb-4 inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-[13px] text-muted">‹ Back to the summary</a>
          <FindingDetail key={detail.id} job={job} report={report} finding={detail} />
        </main>
      ) : (
        <Summary job={job} report={report} />
      )}
    </div>
  );
}

function ReportHeader({ job, report }: { job: Job; report: Report }) {
  const [menu, setMenu] = useState(false);
  const [pack, setPack] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!menu) return;
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === "Escape" : !box.current?.contains(e.target as Node)) setMenu(false);
    };
    window.addEventListener("mousedown", close);
    window.addEventListener("keydown", close);
    return () => { window.removeEventListener("mousedown", close); window.removeEventListener("keydown", close); };
  }, [menu]);

  async function remove() {
    forgetRecent(job.id);
    try { await api.remove(job.id); } finally { navigate("/app"); }
  }
  const evidence = sortFindings(report.findings).filter((f) => f.has_evidence_pcap);
  return (
    <header className="sticky top-0 z-30 border-b border-line bg-bg/90 backdrop-blur">
      <div className="mx-auto flex max-w-[1120px] flex-wrap items-center gap-x-4 gap-y-3 px-4 py-3 sm:px-6">
        <a href={href("/app")} aria-label="Back to the dashboard" className="nt-nav inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-[13px] text-muted">
          ‹<span className="hidden sm:inline"> Dashboard</span>
        </a>
        <span className="hidden h-6 w-px bg-line sm:block" />
        <div className="min-w-0 flex-1 basis-40 sm:basis-56">
          <p className="truncate font-mono text-[13.5px] font-bold text-white" title={`SHA-256 ${report.capture.sha256}`}>{report.capture.file_name}</p>
          <p className="text-[12px] text-muted">
            {bytes(job.size)} · {num(report.ingest.packets_total)} packets · analysed in {duration(report.analysis_seconds)}
          </p>
        </div>
        <div ref={box} className="relative">
          <button type="button" onClick={() => setMenu(!menu)} aria-expanded={menu} aria-haspopup="menu"
            className="nt-btn nt-ghost inline-flex items-center gap-2 rounded-[10px] border border-line bg-surface px-3.5 py-2 font-mono text-[13px] font-semibold">
            <Download size={15} /> Export <ChevronDown size={14} />
          </button>
          {menu && (
            <div role="menu" onClick={() => setMenu(false)}
              className="nt-menu absolute right-0 top-[calc(100%+8px)] z-40 w-[300px] rounded-xl border border-line bg-surface p-1.5 shadow-lift">
              <button type="button" role="menuitem" onClick={() => setPack(true)} className="nt-row flex w-full items-center gap-2.5 rounded-lg px-3 py-2.5 text-left">
                <span className="flex text-neon"><Fingerprint size={15} /></span>
                <span className="min-w-0 flex-1">
                  <span className="block text-[13px] font-semibold">Proof Pack</span>
                  <span className="text-[11.5px] text-muted">Safe to share: addresses hidden, tamper-evident</span>
                </span>
              </button>
              <MenuLink href={api.reportUrl(job.id)} icon={<FileIcon size={15} />} tone="text-neon" title="Full report" sub="JSON, every finding and its evidence" />
              {evidence.map((f) => (
                <MenuLink key={f.id} href={api.evidenceUrl(job.id, f.id)} icon={<Download size={15} />}
                  tone={f.verdict === "attack" ? "text-attack" : "text-fault"} title={`Evidence: ${f.title}`}
                  sub={`.pcap, ${Math.min(f.frames.length, 200)} packets, opens in Wireshark`} />
              ))}
            </div>
          )}
        </div>
        <button type="button" onClick={remove} aria-label="Delete this report now"
          className="nt-btn nt-danger inline-flex items-center gap-2 rounded-[10px] border border-line bg-surface px-3 py-2 font-mono text-[13px] font-semibold sm:px-3.5">
          <Trash size={15} /> <span className="hidden sm:inline">Delete</span>
        </button>
        <a href={href("/app/new")} className="nt-btn nt-primary inline-flex items-center gap-2 rounded-[10px] bg-neon px-3 py-2 font-mono text-[13px] font-bold text-on-primary shadow-glow sm:px-3.5">
          <Plus size={15} /> New<span className="hidden sm:inline"> analysis</span>
        </a>
      </div>
      {pack && <ProofPackDialog jobId={job.id} onClose={() => setPack(false)} />}
    </header>
  );
}

function MenuLink({ href: to, icon, tone, title, sub }: { href: string; icon: ReactNode; tone: string; title: string; sub: string }) {
  return (
    <a role="menuitem" href={to} download className="nt-row flex items-center gap-2.5 rounded-lg px-3 py-2.5">
      <span className={`flex ${tone}`}>{icon}</span>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-[13px] font-semibold">{title}</span>
        <span className="text-[11.5px] text-muted">{sub}</span>
      </span>
    </a>
  );
}

const TONE = {
  attack: { border: "border-attack/50", text: "text-attack", radar: "attack" as const },
  fault: { border: "border-fault/50", text: "text-fault", radar: "fault" as const },
  ok: { border: "border-neon/40", text: "text-neon", radar: "neon" as const },
};
const RING: Record<Verdict, string> = {
  attack: "rgb(var(--attack))", fault: "rgb(var(--fault))", needs_review: "rgb(var(--review))", benign: "rgb(var(--benign))",
};
const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;

function Summary({ job, report }: { job: Job; report: Report }) {
  const [tab, setTab] = useState<"timeline" | "packets" | "integrity">("timeline");
  const [packetsOf, setPacketsOf] = useState<string | null>(null);
  const alerts = sortFindings(report.findings);
  const attacks = alerts.filter((f) => f.verdict === "attack").length;
  const faults = alerts.filter((f) => f.verdict === "fault").length;
  const root = rootFinding(report);
  const toneKey = attacks ? "attack" : faults ? "fault" : "ok";
  const tone = TONE[toneKey];
  const ruled = report.ruled_out.length;
  const title = attacks ? `${plural(attacks, "attack")} found${faults ? `, and ${plural(faults, "fault")}` : ""}`
    : faults ? `${plural(faults, "fault")} found, no attacks` : alerts.length ? "Nothing certain, worth a look" : "No problems found";
  const sentence = root ? firstSentence(root.summary_simple)
    : `${num(report.ingest.packets_total)} packets checked, no problems found${ruled ? `. ${plural(ruled, "thing")} looked suspicious but turned out to be normal.` : "."}`;
  const blips = toneKey === "ok" ? [{ x: 60, y: 34, d: 0.8 }, { x: 32, y: 62, d: 2.0 }]
    : [{ x: 66, y: 32, d: 0.3, tone: tone.radar }, { x: 30, y: 60, d: 1.5, tone: tone.radar }];
  const withPackets = alerts.filter((f) => f.key_packets.length);

  const showPackets = (id: string) => {
    setPacketsOf(id);
    setTab("packets");
    document.getElementById("details")?.scrollIntoView({ behavior: "smooth" });
  };

  return (
    <main className="mx-auto flex max-w-[1120px] flex-col gap-6 px-4 pb-20 pt-8 sm:px-6">
      <section className={`console-bg relative overflow-hidden rounded-[20px] border p-6 shadow-lift sm:p-8 ${tone.border}`}>
        <div className="relative z-[1] flex flex-wrap items-center gap-7">
          <div className="w-28 shrink-0 sm:w-[150px]"><RadarDish tone={tone.radar} active blips={blips} className="w-full" /></div>
          <div className="flex min-w-0 flex-1 basis-[420px] flex-col items-start gap-3">
            <p className={`font-mono text-[11px] font-semibold uppercase tracking-[0.2em] ${tone.text}`}>Verdict</p>
            <h1 className={`glow-text font-mono text-[clamp(28px,3.2vw,36px)] font-bold leading-tight tracking-[-0.025em] ${tone.text}`}>{title}</h1>
            <p className="max-w-[640px] text-[16.5px] leading-relaxed">{sentence}</p>
            <div className="flex flex-wrap gap-2 font-mono text-[12px]">
              {root && <span className={`rounded-full border px-2.5 py-1 ${tone.border} ${tone.text}`}>{pct(root.confidence)} sure</span>}
              <span className="rounded-full border border-line px-2.5 py-1 text-muted">{duration(report.capture.duration)} of traffic</span>
              <span className="rounded-full border border-line px-2.5 py-1 text-muted">{plural(report.devices, "device")}</span>
              {ruled > 0 && <span className="rounded-full border border-benign/40 px-2.5 py-1 text-benign">{plural(ruled, "look-alike")} ruled out</span>}
            </div>
            {root && (
              <div className="mt-1 flex flex-wrap gap-2.5">
                <button type="button" onClick={() => document.getElementById("todo")?.scrollIntoView({ behavior: "smooth" })}
                  className="nt-btn nt-primary inline-flex items-center gap-2 rounded-[10px] bg-neon px-[18px] py-2.5 font-mono text-[13.5px] font-bold text-on-primary shadow-glow">
                  What to do <span className="nt-arrow">↓</span>
                </button>
                <button type="button" onClick={() => document.getElementById("found")?.scrollIntoView({ behavior: "smooth" })}
                  className="nt-btn nt-ghost inline-flex items-center gap-2 rounded-[10px] border border-line bg-surface/80 px-[18px] py-2.5 font-mono text-[13.5px] font-semibold">
                  Why we think so
                </button>
              </div>
            )}
          </div>
        </div>
        <div className="scanlines pointer-events-none absolute inset-0 opacity-35" />
      </section>

      {report.quality.map((q) => (
        <div key={q.code} className="flex items-start gap-3 rounded-2xl border border-review/40 bg-review/5 p-4">
          <Info size={18} className="mt-0.5 shrink-0 text-review" />
          <div>
            <p className="font-semibold">{q.message}</p>
            {q.detail && <p className="mt-0.5 text-[13px] text-muted">{q.detail}</p>}
          </div>
        </div>
      ))}

      {root && root.fix_steps.length > 0 && <Checklist key={root.id} finding={root} />}

      {alerts.length > 0 && (
        <section id="found" className="flex scroll-mt-24 flex-col gap-3.5">
          <h2 className="text-[16px] font-semibold text-white">What we found</h2>
          {(report.incidents ?? []).map((inc) => (
            <div key={inc.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-xl border border-amber/40 bg-amber/5 px-4 py-3 text-[13.5px]">
              <span className="font-mono text-[11px] font-semibold uppercase tracking-[0.16em] text-amber">Connected</span>
              <span className="font-semibold">{inc.title}</span>
            </div>
          ))}
          <div className="grid items-start gap-4 lg:grid-cols-2">
            {alerts.map((f, i) => <FindingCard key={f.id} job={job} f={f} open={i === 0} onPackets={() => showPackets(f.id)} />)}
          </div>
        </section>
      )}

      {(report.exposures ?? []).map((e) => <BlastRadius key={e.finding_id} exposure={e} start={report.capture.first_ts} />)}

      {ruled > 0 && <RuledOut report={report} />}

      <section id="details" className="scroll-mt-24">
        <div role="tablist" className="mb-4 flex flex-wrap gap-1 rounded-xl border border-line bg-surface p-1.5 font-mono text-[13px] font-semibold">
          <TabButton on={tab === "timeline"} onClick={() => setTab("timeline")} icon={<Bars size={15} />}>Timeline</TabButton>
          {withPackets.length > 0 && (
            <TabButton on={tab === "packets"} onClick={() => setTab("packets")} icon={<List size={15} />}>Packets</TabButton>
          )}
          <TabButton on={tab === "integrity"} onClick={() => setTab("integrity")} icon={<Fingerprint size={15} />}>Integrity</TabButton>
        </div>
        <div key={tab} className="nt-open">
          {tab === "timeline" && <TimelineTab job={job} report={report} />}
          {tab === "packets" && <Packets job={job} findings={withPackets} selected={packetsOf} onSelect={setPacketsOf} start={report.capture.first_ts} />}
          {tab === "integrity" && <IntegrityTab job={job} report={report} />}
        </div>
      </section>
    </main>
  );
}

function TabButton({ on, onClick, icon, children }: { on: boolean; onClick: () => void; icon: ReactNode; children: ReactNode }) {
  return (
    <button type="button" role="tab" aria-selected={on} onClick={onClick}
      className={`flex items-center gap-2 rounded-[10px] px-3.5 py-2 transition-colors ${on ? "bg-neon/[0.12] text-neon" : "text-muted hover:text-ink"}`}>
      {icon} {children}
    </button>
  );
}

function Checklist({ finding }: { finding: Finding }) {
  const [done, setDone] = useState<boolean[]>(() => finding.fix_steps.map(() => false));
  const count = done.filter(Boolean).length;
  return (
    <section id="todo" className="scroll-mt-24 overflow-hidden rounded-[18px] border border-line bg-surface shadow-card">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-[22px] py-[18px]">
        <h2 className="flex items-center gap-2.5 text-[16px] font-semibold text-white"><span className="text-neon"><Wrench size={17} /></span> What to do</h2>
        <span className="flex items-center gap-2.5 font-mono text-[12px] text-muted">
          {count} of {done.length} done
          <span className="h-1.5 w-[120px] overflow-hidden rounded-full bg-line">
            <span className="block h-full rounded-full bg-neon transition-all duration-500" style={{ width: `${(count / done.length) * 100}%` }} />
          </span>
        </span>
      </header>
      <ol className="flex flex-col gap-0.5 p-2">
        {finding.fix_steps.map((s, i) => (
          <li key={s}>
            <label className="flex cursor-pointer items-start gap-3.5 rounded-xl px-3.5 py-3 transition-colors hover:bg-neon/5">
              <input type="checkbox" checked={done[i]} onChange={() => setDone(done.map((d, j) => (j === i ? !d : d)))}
                className="mt-1 h-[18px] w-[18px] shrink-0 accent-[rgb(var(--neon))]" />
              <span className={`leading-relaxed transition-colors ${done[i] ? "text-muted line-through" : ""}`}>{s}</span>
            </label>
          </li>
        ))}
      </ol>
    </section>
  );
}

function Ring({ value, verdict }: { value: number; verdict: Verdict }) {
  const c = 113;
  return (
    <span className="relative h-12 w-12 shrink-0" title={`${pct(value)} confident`}>
      <svg width="48" height="48" viewBox="0 0 48 48" aria-hidden="true">
        <circle cx="24" cy="24" r="18" fill="none" stroke="rgb(var(--line))" strokeWidth="4" />
        <circle className="nt-ring" cx="24" cy="24" r="18" fill="none" stroke={RING[verdict]} strokeWidth="4" strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={c * (1 - value)} transform="rotate(-90 24 24)" />
      </svg>
      <span className="absolute inset-0 flex items-center justify-center font-mono text-[11px] font-bold text-white">{pct(value)}</span>
    </span>
  );
}

function FindingCard({ job, f, open, onPackets }: { job: Job; f: Finding; open: boolean; onPackets: () => void }) {
  const [why, setWhy] = useState(open);
  const winner = f.hypotheses[0];
  const reasons = (winner?.evidence ?? []).filter((e) => e.weight > 0).sort((a, b) => b.weight - a.weight).slice(0, 4);
  const others = f.hypotheses.slice(1).filter((h) => h.probability < 0.05);
  return (
    <article className={`nt-lift ${f.verdict === "attack" ? "nt-lift-attack" : ""} flex flex-col gap-3.5 rounded-[18px] border border-line bg-surface p-[22px] shadow-card`}>
      <div className="flex items-center justify-between gap-3">
        <span className="flex items-center gap-2.5"><VerdictChip verdict={f.verdict} /><SeverityBadge severity={f.severity} /></span>
        <Ring value={f.confidence} verdict={f.verdict} />
      </div>
      <h3 className="text-[17px] font-semibold leading-snug text-white">{f.title}</h3>
      <p className="leading-relaxed text-muted">{f.summary_simple}</p>
      {f.entities.length > 0 && (
        <div className="flex flex-wrap gap-1.5">{f.entities.slice(0, 3).map((e) => <EntityChip key={`${e.kind}-${e.value}-${e.role}`} {...e} />)}</div>
      )}
      {(f.techniques ?? []).length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {f.techniques!.map((t) => (
            <a key={t.id} href={t.url} target="_blank" rel="noreferrer noopener" title={t.name}
              className="inline-flex items-center gap-1.5 rounded-md border border-attack/35 bg-attack/[0.06] px-2 py-0.5 font-mono text-[11px] text-attack transition-colors hover:border-attack/70">
              ATT&amp;CK {t.id} <span className="hidden text-muted sm:inline">{t.name.replace("Adversary-in-the-Middle: ", "")}</span>
            </a>
          ))}
        </div>
      )}
      <div className="flex flex-wrap gap-4 border-t border-line pt-3 font-mono text-[12.5px] font-semibold">
        <button type="button" onClick={() => setWhy(!why)} aria-expanded={why} className="nt-toggle inline-flex items-center gap-1.5 text-neon">
          Why we think so <span className={`inline-block transition-transform ${why ? "rotate-180" : ""}`}><ChevronDown size={14} /></span>
        </button>
        {f.key_packets.length > 0 && (
          <button type="button" onClick={onPackets} className="nt-toggle inline-flex items-center gap-1.5 text-muted">See the packets <span className="nt-arrow">›</span></button>
        )}
        <a href={href(`/a/${job.id}/findings/${f.id}`)} className="nt-toggle ml-auto inline-flex items-center gap-1.5 text-muted">Full details <span className="nt-arrow">›</span></a>
      </div>
      {why && (
        <ul className="nt-open flex flex-col gap-2.5 rounded-xl bg-bg p-3.5 text-[13px] leading-relaxed">
          {reasons.map((e) => (
            <li key={e.reason} className="flex gap-2.5"><span className="shrink-0 font-bold text-neon">+</span>{e.reason}</li>
          ))}
          {others.length > 0 && (
            <li className="flex gap-2.5 text-muted">
              <span className="shrink-0 font-bold text-benign">✓</span>
              <span>Ruled out: {others.map((h) => h.label).join(", ")} ({others.length === 1 ? pct(others[0].probability) : "each under 5%"}).</span>
            </li>
          )}
        </ul>
      )}
    </article>
  );
}

function RuledOut({ report }: { report: Report }) {
  const [open, setOpen] = useState(false);
  const n = report.ruled_out.length;
  return (
    <div className="rounded-[14px] border border-line bg-surface">
      <button type="button" onClick={() => setOpen(!open)} aria-expanded={open} className="nt-toggle flex w-full items-center gap-2.5 px-[18px] py-3.5 text-left">
        <span className="text-benign"><CheckCircle size={17} /></span>
        <span className="flex-1 font-semibold text-ink">{n === 1 ? "1 thing looked suspicious but is normal" : `${n} things looked suspicious but are normal`}</span>
        <span className={`text-muted transition-transform ${open ? "rotate-180" : ""}`}><ChevronDown size={16} /></span>
      </button>
      {open && (
        <ul className="nt-open flex flex-col gap-3 px-[18px] pb-4 pl-[46px]">
          {sortFindings(report.ruled_out).map((f) => (
            <li key={f.id} className="flex flex-col gap-1">
              <span className="flex flex-wrap items-center gap-2"><VerdictChip verdict={f.verdict} size="sm" /><span className="font-medium">{f.title}</span>
                <span className="font-mono text-[12px] text-muted">{pct(f.confidence)} sure</span></span>
              <span className="text-[13px] text-muted">{firstSentence(f.summary_simple)}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Packets({ job, findings, selected, onSelect, start }: {
  job: Job; findings: Finding[]; selected: string | null; onSelect: (id: string) => void; start: number | null;
}) {
  const f = findings.find((x) => x.id === selected) ?? findings[0];
  if (!f) return null;
  return (
    <div className="flex flex-col gap-3.5">
      {findings.length > 1 && (
        <div className="flex flex-wrap gap-1.5 text-[12.5px]" role="group" aria-label="Packets for">
          {findings.map((x) => (
            <button key={x.id} type="button" aria-pressed={x.id === f.id} onClick={() => onSelect(x.id)}
              className={`max-w-full truncate rounded-full border px-3 py-1 transition-colors ${x.id === f.id ? "border-neon/50 bg-neon/10 text-neon" : "border-line text-muted hover:text-ink"}`}>
              {x.title}
            </button>
          ))}
        </div>
      )}
      <div className="overflow-x-auto rounded-xl border border-line bg-surface">
        <table className="w-full min-w-[680px] text-left">
          <thead className="bg-raised text-[11.5px] text-muted">
            <tr><th className="px-3.5 py-2 font-semibold">No.</th><th className="px-3.5 py-2 font-semibold">Time</th><th className="px-3.5 py-2 font-semibold">From</th>
              <th className="px-3.5 py-2 font-semibold">To</th><th className="px-3.5 py-2 font-semibold">Protocol</th><th className="px-3.5 py-2 font-semibold">What happened</th></tr>
          </thead>
          <tbody className="mono">
            {f.key_packets.map((k) => (
              <tr key={`${k.frame}-${k.summary}`} className="nt-row border-t border-line align-top">
                <td className="px-3.5 py-2 tabular-nums text-neon">{k.frame}</td>
                <td className="whitespace-nowrap px-3.5 py-2 text-muted">{offset(k.ts, start)}</td>
                <td className="whitespace-nowrap px-3.5 py-2">{k.src}</td>
                <td className="whitespace-nowrap px-3.5 py-2">{k.dst}</td>
                <td className="px-3.5 py-2">{k.protocol}</td>
                <td className="min-w-[280px] break-words px-3.5 py-2">{k.summary}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-2.5 rounded-xl border border-line bg-surface px-3.5 py-3">
        <code className="mono min-w-0 break-all text-amber">{f.wireshark_filter}</code>
        <span className="flex gap-2">
          <CopyButton text={f.wireshark_filter} label="Copy Wireshark filter" />
          {f.has_evidence_pcap && (
            <a href={api.evidenceUrl(job.id, f.id)} download className="btn btn-primary px-2.5 py-1 text-[12px]"><Download size={13} /> evidence.pcap</a>
          )}
        </span>
      </div>
      <p className="text-[12px] text-muted">Frame numbers match Wireshark's "No." column.</p>
    </div>
  );
}
