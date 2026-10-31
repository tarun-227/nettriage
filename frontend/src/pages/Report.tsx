import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { SEVERITY_ORDER, clock, duration, num, offset } from "../lib/format";
import { addRecent, forgetRecent } from "../lib/recent";
import { href, navigate } from "../lib/router";
import type { Finding, Job, Report, Verdict } from "../lib/types";
import {
  Activity, Bars, CheckCircle, ChevronDown, ChevronRight, Download, Fingerprint, Info, List, Plus, Trash, Wrench,
} from "../components/icons";
import { VerdictSeal } from "../components/Scene3D";
import { TimelineChart } from "../components/TimelineChart";
import { Tilt } from "../components/Tilt";
import { TopBar } from "../components/TopBar";
import { ConfidenceBar, EntityChip, SeverityBadge, VerdictChip } from "../components/ui";
import { FindingDetail } from "./FindingDetail";
import { IntegrityTab } from "./Integrity";
import { TimelineTab } from "./Timeline";

const TABS = [
  { key: "overview", label: "Overview", Icon: Activity },
  { key: "findings", label: "Findings", Icon: List },
  { key: "timeline", label: "Timeline", Icon: Bars },
  { key: "integrity", label: "Integrity", Icon: Fingerprint },
] as const;

export function ReportView({ job, report, rest }: { job: Job; report: Report; rest: string[] }) {
  const tab = TABS.some((t) => t.key === rest[0]) ? rest[0] : "overview";
  const base = `/a/${job.id}`;
  const alerts = report.findings;
  const counts = {
    attack: alerts.filter((f) => f.verdict === "attack").length,
    fault: alerts.filter((f) => f.verdict === "fault").length,
    review: alerts.filter((f) => f.verdict === "needs_review").length,
  };

  useEffect(() => {
    addRecent({ id: job.id, name: report.capture.file_name, at: Date.now(), attacks: counts.attack, faults: counts.fault });
  }, [job.id, report.capture.file_name, counts.attack, counts.fault]);

  async function remove() {
    forgetRecent(job.id);
    try {
      await api.remove(job.id);
    } finally {
      navigate("/");
    }
  }

  return (
    <div className="flex min-h-full flex-col">
      <TopBar>
        <span className="hidden h-6 w-px bg-white/20 md:block" />
        <div className="hidden min-w-0 md:block">
          <p className="truncate text-[13px] font-semibold">{report.capture.file_name}</p>
          <p className="mono truncate text-[11px] text-white/55" title={`SHA-256 ${report.capture.sha256}`}>
            sha256 {report.capture.sha256.slice(0, 16)}...
          </p>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <a className="btn btn-ghost-light px-2.5" href={api.reportUrl(job.id)} download title="Download the full report as JSON">
            <Download size={15} /><span className="hidden xl:inline">Export</span>
          </a>
          <button type="button" className="btn btn-ghost-light px-2.5" onClick={remove} title="Forget this report now">
            <Trash size={15} /><span className="hidden xl:inline">Delete</span>
          </button>
          <a className="btn btn-gold" href={href("/")}><Plus size={15} /><span className="hidden sm:inline">New analysis</span></a>
        </div>
      </TopBar>
      <div className="mx-auto flex w-full max-w-[1400px] flex-1">
        <nav className="sticky top-16 hidden h-[calc(100vh-4rem)] w-56 shrink-0 border-r border-line p-4 md:block" aria-label="Report">
          <a href={href("/")} className="mb-4 flex items-center gap-1.5 text-[12.5px] text-muted hover:text-primary">
            <ChevronRight size={13} className="rotate-180" /> Home
          </a>
          <ul className="space-y-1">
            {TABS.map(({ key, label, Icon }) => (
              <li key={key}>
                <a href={href(`${base}/${key}`)}
                  className={`flex items-center gap-2.5 rounded-xl px-3 py-2 text-[13.5px] font-semibold transition-colors ${tab === key
                    ? "bg-navy text-white shadow-card" : "text-muted hover:bg-raised hover:text-ink"}`}>
                  <Icon size={16} className={tab === key ? "text-gold" : ""} />
                  {label}
                  {key === "findings" && alerts.length > 0 && (
                    <span className={`ml-auto rounded-md px-1.5 text-[11px] tabular-nums ${tab === key ? "bg-gold text-navy" : "bg-raised"}`}>
                      {alerts.length}
                    </span>
                  )}
                </a>
              </li>
            ))}
          </ul>
          <div className="mt-6 space-y-2.5 rounded-xl border border-line bg-surface p-3 text-[12.5px]">
            <Stat label="Attacks" value={counts.attack} cls="text-attack" />
            <Stat label="Faults" value={counts.fault} cls="text-fault" />
            <Stat label="Needs review" value={counts.review} cls="text-review" />
            <Stat label="Ruled out" value={report.ruled_out.length} cls="text-benign" />
          </div>
        </nav>
        <main className="min-w-0 flex-1 px-4 py-6 sm:px-8">
          <div className="mb-4 flex gap-1 overflow-x-auto md:hidden">
            {TABS.map(({ key, label }) => (
              <a key={key} href={href(`${base}/${key}`)}
                className={`rounded-lg px-3 py-1.5 text-[13px] font-semibold ${tab === key ? "bg-navy text-white" : "text-muted"}`}>{label}</a>
            ))}
          </div>
          {tab === "overview" && <Overview job={job} report={report} />}
          {tab === "findings" && <FindingsTab job={job} report={report} selected={rest[1]} />}
          {tab === "timeline" && <TimelineTab job={job} report={report} />}
          {tab === "integrity" && <IntegrityTab job={job} report={report} />}
        </main>
      </div>
    </div>
  );
}

function Stat({ label, value, cls }: { label: string; value: number; cls: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-muted">{label}</span>
      <span className={`font-semibold tabular-nums ${value ? cls : "text-muted"}`}>{value}</span>
    </div>
  );
}

function headline(report: Report): { text: string; tone: "attack" | "fault" | "ok" } {
  const attacks = report.findings.filter((f) => f.verdict === "attack");
  const faults = report.findings.filter((f) => f.verdict === "fault");
  const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;
  if (attacks.length) {
    const also = faults.length ? ` and ${plural(faults.length, "fault")}` : "";
    return { text: `${plural(attacks.length, "attack")}${also} found`, tone: "attack" };
  }
  if (faults.length) return { text: `No attacks, but ${plural(faults.length, "problem")} with the network`, tone: "fault" };
  return { text: "No problems found", tone: "ok" };
}

function Overview({ job, report }: { job: Job; report: Report }) {
  const h = headline(report);
  const start = report.capture.first_ts;
  const top = sortFindings(report.findings)[0];
  const incidents = report.incidents ?? [];
  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div className="hero-bg relative overflow-hidden rounded-3xl p-6 text-white shadow-lift sm:p-8">
        <div className="flex items-start gap-5">
          <VerdictSeal tone={h.tone} />
          <div className="min-w-0">
            <p className="eyebrow">Diagnosis</p>
            <h1 className="display mt-1 text-[28px] font-semibold leading-tight sm:text-[32px]">{h.text}</h1>
            <p className="mt-2 text-[14px] text-white/75">
              {num(report.ingest.packets_total)} packets over {duration(report.capture.duration)} from {report.devices} devices,
              analysed in {duration(report.analysis_seconds)}.
              {report.ruled_out.length > 0 && ` ${report.ruled_out.length} suspicious-looking thing${report.ruled_out.length === 1 ? " was" : "s were"} checked and ruled out.`}
            </p>
          </div>
        </div>
      </div>

      {top && (
        <a href={href(`/a/${job.id}/findings/${top.id}`)}
          className="card group flex flex-col gap-3 border-l-4 border-l-gold p-5 transition-shadow hover:shadow-lift sm:flex-row sm:items-center">
          <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-gold/15 text-primary"><Wrench size={19} /></span>
          <span className="min-w-0 flex-1">
            <span className="label">Start here</span>
            <span className="mt-0.5 block text-[15px] font-semibold">{top.title}</span>
            <span className="mt-0.5 block text-[13.5px] text-muted">First step: {top.fix_steps[0]}</span>
          </span>
          <span className="flex shrink-0 items-center gap-1 text-[13px] font-semibold text-primary">
            Why and how <ChevronRight size={15} className="transition-transform group-hover:translate-x-0.5" />
          </span>
        </a>
      )}

      {report.quality.map((q) => (
        <div key={q.code} className="flex items-start gap-3 rounded-2xl border border-review/40 bg-review/5 p-4">
          <Info size={18} className="mt-0.5 shrink-0 text-review" />
          <div>
            <p className="font-semibold">{q.message}</p>
            {q.detail && <p className="mt-0.5 text-[13px] text-muted">{q.detail}</p>}
          </div>
        </div>
      ))}

      {incidents.length > 0 && (
        <div className="card overflow-hidden">
          <p className="label border-b border-line px-5 py-3">Connected findings</p>
          <ul className="divide-y divide-line">
            {incidents.map((inc) => (
              <li key={inc.id} className="px-5 py-4">
                <div className="flex flex-wrap items-center gap-2">
                  <VerdictChip verdict={inc.verdict} size="sm" />
                  <span className="font-semibold">{inc.title}</span>
                </div>
                <p className="mt-1 text-[13.5px] leading-relaxed text-muted">{inc.summary}</p>
                <div className="mt-2 flex flex-wrap gap-2">
                  {inc.finding_ids.map((fid) => {
                    const f = [...report.findings, ...report.ruled_out].find((x) => x.id === fid);
                    return f ? (
                      <a key={fid} href={href(`/a/${job.id}/findings/${fid}`)}
                        className="inline-flex items-center gap-1 rounded-lg border border-line bg-raised px-2 py-1 text-[12.5px] hover:border-primary/40">
                        {fid === inc.root_finding && <span className="font-semibold text-primary">Root cause:</span>} {f.title}
                      </a>
                    ) : null;
                  })}
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <Kpi label="Packets" value={num(report.ingest.packets_total)}
          sub={report.ingest.packets_skipped ? `${num(report.ingest.packets_skipped)} skipped` : "all decoded"} />
        <Kpi label="Duration" value={duration(report.capture.duration)} sub={start ? clock(start) : ""} />
        <Kpi label="Devices" value={String(report.devices)} sub={`${report.hosts} IP addresses`} />
        <Kpi label="Attacks" value={String(report.findings.filter((f) => f.verdict === "attack").length)} tone="text-attack" />
        <Kpi label="Faults" value={String(report.findings.filter((f) => f.verdict === "fault").length)} tone="text-fault" />
        <Kpi label="Ruled out" value={String(report.ruled_out.length)} tone="text-benign" sub="checked, not a problem" />
      </div>

      <div className="card p-5">
        <div className="mb-3 flex items-center justify-between">
          <p className="label">Traffic and findings over time</p>
          <a className="link text-[12.5px]" href={href(`/a/${job.id}/timeline`)}>Open timeline</a>
        </div>
        <TimelineChart report={report} jobId={job.id} height={120} />
      </div>

      <FindingGroups job={job} report={report} />
      <div className="grid gap-5 lg:grid-cols-2">
        <ProtocolMix report={report} />
        <Inventory report={report} />
      </div>
    </div>
  );
}

function Kpi({ label, value, sub, tone }: { label: string; value: string; sub?: string; tone?: string }) {
  return (
    <Tilt className="rounded-2xl" max={6}>
      <div className="card h-full px-4 py-3.5">
        <p className="label">{label}</p>
        <p className={`display mt-1 text-[26px] font-semibold tabular-nums leading-tight ${tone && value !== "0" ? tone : ""}`}>{value}</p>
        {sub && <p className="truncate text-[12px] text-muted">{sub}</p>}
      </div>
    </Tilt>
  );
}

export function sortFindings(list: Finding[]): Finding[] {
  const order = { attack: 0, fault: 1, needs_review: 2, benign: 3 };
  return [...list].sort((a, b) => order[a.verdict] - order[b.verdict]
    || SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.confidence - a.confidence);
}

function FindingGroups({ job, report }: { job: Job; report: Report }) {
  const [open, setOpen] = useState(false);
  const groups = [
    { title: "Attacks", items: report.findings.filter((f) => f.verdict === "attack") },
    { title: "Faults", items: report.findings.filter((f) => f.verdict === "fault") },
    { title: "Needs review", items: report.findings.filter((f) => f.verdict === "needs_review") },
  ].filter((g) => g.items.length);
  return (
    <div className="space-y-5">
      {groups.map((g) => (
        <div key={g.title} className="card overflow-hidden">
          <p className="label border-b border-line px-5 py-3">{g.title}</p>
          <FindingRows job={job} items={g.items} start={report.capture.first_ts} />
        </div>
      ))}
      {report.ruled_out.length > 0 && (
        <div className="card overflow-hidden">
          <button type="button" onClick={() => setOpen(!open)} aria-expanded={open}
            className="flex w-full items-center gap-2 px-5 py-3.5 text-left hover:bg-raised/60">
            {open ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
            <CheckCircle size={16} className="text-benign" />
            <span className="font-semibold">Checked and ruled out</span>
            <span className="text-muted">({report.ruled_out.length}) Looked suspicious, but the evidence says it's normal.</span>
          </button>
          {open && <FindingRows job={job} items={report.ruled_out} start={report.capture.first_ts} />}
        </div>
      )}
    </div>
  );
}

export function FindingRows({ job, items, start }: { job: Job; items: Finding[]; start: number | null }) {
  return (
    <ul className="divide-y divide-line">
      {items.map((f) => (
        <li key={f.id}>
          <a href={href(`/a/${job.id}/findings/${f.id}`)}
            className="flex flex-col gap-2 px-5 py-3.5 transition-colors hover:bg-raised/60 sm:flex-row sm:items-center sm:gap-4">
            <div className="flex min-w-0 flex-1 items-start gap-3">
              <VerdictChip verdict={f.verdict} size="sm" />
              <div className="min-w-0">
                <p className="truncate font-semibold">{f.title}</p>
                <div className="mt-1 flex flex-wrap gap-1.5">
                  {f.entities.slice(0, 3).map((e) => <EntityChip key={`${e.kind}-${e.value}-${e.role}`} {...e} />)}
                </div>
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-4 pl-[92px] sm:pl-0">
              <SeverityBadge severity={f.severity} />
              <ConfidenceBar value={f.confidence} verdict={f.verdict} width="w-16" />
              <span className="mono hidden w-20 text-right text-muted lg:block">{offset(f.time_start, start)}</span>
              <ChevronRight size={15} className="hidden text-muted sm:block" />
            </div>
          </a>
        </li>
      ))}
    </ul>
  );
}

function ProtocolMix({ report }: { report: Report }) {
  const entries = Object.entries(report.protocols);
  const total = entries.reduce((s, [, n]) => s + n, 0);
  if (!total) return null;
  const colours = ["bg-navy", "bg-gold", "bg-review", "bg-benign", "bg-fault", "bg-muted", "bg-attack/70", "bg-ink/30"];
  return (
    <div className="card h-fit p-5">
      <p className="label mb-3">Protocol mix</p>
      <div className="flex h-3 overflow-hidden rounded-full bg-raised">
        {entries.map(([name, n], i) => (
          <span key={name} className={colours[i % colours.length]} style={{ width: `${(n / total) * 100}%` }} title={`${name}: ${num(n)}`} />
        ))}
      </div>
      <ul className="mt-3 flex flex-wrap gap-x-5 gap-y-1.5 text-[12.5px]">
        {entries.map(([name, n], i) => (
          <li key={name} className="flex items-center gap-1.5">
            <span className={`h-2.5 w-2.5 rounded-sm ${colours[i % colours.length]}`} />
            {name} <span className="tabular-nums text-muted">{((n / total) * 100).toFixed(1)}%</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

// Text taken straight from packets (names, hostnames). The server escaped it, and React renders
// it as plain text, so a hostname like "<script>" is just shown, never run.
function Inventory({ report }: { report: Report }) {
  if (!report.names.length && !report.device_names.length) return null;
  return (
    <div className="card p-5">
      <p className="label mb-3">Names and devices seen</p>
      {report.device_names.length > 0 && (
        <div className="mb-4">
          <p className="mb-1.5 text-[12px] text-muted">Devices that announced a hostname (DHCP)</p>
          <ul className="space-y-1">
            {report.device_names.slice(0, 8).map((d) => (
              <li key={d.mac} className="flex items-baseline gap-2 text-[13px]">
                <span className="mono shrink-0 text-muted">{d.mac}</span>
                <span className="mono min-w-0 break-all">{d.hostname ?? "(no name)"}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {report.names.length > 0 && (
        <div>
          <p className="mb-1.5 text-[12px] text-muted">Most looked-up names (DNS)</p>
          <ul className="space-y-1">
            {report.names.slice(0, 10).map((n) => (
              <li key={n.name} className="flex items-baseline justify-between gap-3 text-[13px]">
                <span className="mono min-w-0 break-all">{n.name}</span>
                <span className="shrink-0 tabular-nums text-muted">{n.count}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

const FILTERS: { key: "all" | Verdict; label: string }[] = [
  { key: "all", label: "All" },
  { key: "attack", label: "Attacks" },
  { key: "fault", label: "Faults" },
  { key: "needs_review", label: "Needs review" },
  { key: "benign", label: "Ruled out" },
];

function FindingsTab({ job, report, selected }: { job: Job; report: Report; selected?: string }) {
  const [filter, setFilter] = useState<"all" | Verdict>("all");
  const all = [...sortFindings(report.findings), ...sortFindings(report.ruled_out)];
  const visible = filter === "all" ? all : all.filter((f) => f.verdict === filter);
  const current = all.find((f) => f.id === selected) ?? visible[0] ?? all[0];
  if (!all.length) {
    return <div className="card mx-auto max-w-3xl p-10 text-center text-muted">Nothing to report in this capture.</div>;
  }
  return (
    <div className="grid gap-5 xl:grid-cols-[minmax(320px,400px)_1fr]">
      <div className="card h-fit overflow-hidden xl:sticky xl:top-[5.5rem] xl:max-h-[calc(100vh-7rem)] xl:overflow-y-auto">
        <div className="flex flex-wrap gap-1 border-b border-line p-2.5">
          {FILTERS.map((fl) => {
            const n = fl.key === "all" ? all.length : all.filter((f) => f.verdict === fl.key).length;
            if (fl.key !== "all" && !n) return null;
            return (
              <button key={fl.key} type="button" onClick={() => setFilter(fl.key)} aria-pressed={filter === fl.key}
                className={`rounded-lg px-2.5 py-1 text-[12.5px] font-semibold transition-colors ${filter === fl.key
                  ? "bg-navy text-white" : "text-muted hover:bg-raised hover:text-ink"}`}>
                {fl.label} <span className={filter === fl.key ? "text-gold" : ""}>{n}</span>
              </button>
            );
          })}
        </div>
        <ul className="divide-y divide-line">
          {visible.map((f) => (
            <li key={f.id}>
              <a href={href(`/a/${job.id}/findings/${f.id}`)}
                className={`block px-4 py-3 transition-colors hover:bg-raised/60 ${current?.id === f.id ? "bg-raised shadow-[inset_3px_0_0_rgb(var(--gold))]" : ""}`}>
                <div className="flex items-center justify-between gap-2">
                  <VerdictChip verdict={f.verdict} size="sm" />
                  <ConfidenceBar value={f.confidence} verdict={f.verdict} width="w-12" />
                </div>
                <p className="mt-1.5 line-clamp-2 text-[13px] font-semibold leading-snug">{f.title}</p>
              </a>
            </li>
          ))}
        </ul>
      </div>
      {current && <FindingDetail key={current.id} job={job} report={report} finding={current} />}
    </div>
  );
}
