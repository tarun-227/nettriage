import { useState } from "react";
import { api } from "../lib/api";
import { SEVERITY_ORDER, clock, duration, num, offset } from "../lib/format";
import { href, navigate } from "../lib/router";
import type { Finding, Job, Report } from "../lib/types";
import {
  Activity, Alert, Bars, CheckCircle, ChevronDown, ChevronRight, Download, Fingerprint, Info, List, Plus, Trash,
} from "../components/icons";
import { TopBar } from "../components/TopBar";
import { TimelineChart } from "../components/TimelineChart";
import { ConfidenceBar, EntityChip, SeverityBadge, VerdictChip } from "../components/ui";
import { FindingDetail } from "./FindingDetail";
import { TimelineTab } from "./Timeline";
import { IntegrityTab } from "./Integrity";

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

  async function remove() {
    try {
      await api.remove(job.id);
    } finally {
      navigate("/");
    }
  }

  return (
    <div className="flex min-h-full flex-col">
      <TopBar>
        <span className="hidden h-5 w-px bg-line md:block" />
        <div className="hidden min-w-0 md:block">
          <p className="truncate text-[13px] font-medium">{report.capture.file_name}</p>
          <p className="mono truncate text-[11px] text-muted" title={`SHA-256 ${report.capture.sha256}`}>
            sha256 {report.capture.sha256.slice(0, 16)}...
          </p>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <a className="btn" href={api.reportUrl(job.id)} download><Download size={14} /><span className="hidden lg:inline">Export JSON</span></a>
          <button type="button" className="btn btn-danger" onClick={remove} title="Forget this report now">
            <Trash size={14} /><span className="hidden lg:inline">Delete now</span>
          </button>
          <a className="btn btn-primary" href={href("/")}><Plus size={14} /><span className="hidden lg:inline">New analysis</span></a>
        </div>
      </TopBar>
      <div className="flex flex-1">
        <nav className="sticky top-14 hidden h-[calc(100vh-3.5rem)] w-52 shrink-0 border-r border-line p-3 md:block">
          <ul className="space-y-0.5">
            {TABS.map(({ key, label, Icon }) => (
              <li key={key}>
                <a href={href(`${base}/${key}`)}
                  className={`flex items-center gap-2.5 rounded-lg px-3 py-2 text-[13px] font-medium transition-colors ${tab === key
                    ? "bg-raised text-ink" : "text-muted hover:bg-raised/60 hover:text-ink"}`}>
                  <Icon size={15} />
                  {label}
                  {key === "findings" && alerts.length > 0 && (
                    <span className="ml-auto rounded-md bg-line px-1.5 text-[11px] tabular-nums">{alerts.length}</span>
                  )}
                </a>
              </li>
            ))}
          </ul>
          <div className="mt-6 space-y-2 border-t border-line pt-4 text-[12px]">
            <Stat label="Attacks" value={counts.attack} cls="text-attack" />
            <Stat label="Faults" value={counts.fault} cls="text-fault" />
            <Stat label="Needs review" value={counts.review} cls="text-review" />
            <Stat label="Ruled out" value={report.ruled_out.length} cls="text-benign" />
          </div>
        </nav>
        <main className="min-w-0 flex-1 px-4 py-5 sm:px-6">
          <div className="mb-4 flex gap-1 overflow-x-auto md:hidden">
            {TABS.map(({ key, label }) => (
              <a key={key} href={href(`${base}/${key}`)}
                className={`rounded-md px-3 py-1.5 text-[13px] ${tab === key ? "bg-raised" : "text-muted"}`}>{label}</a>
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
    <div className="flex items-center justify-between px-3">
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
    return { text: `${plural(attacks.length, "attack")}${also} found. Most urgent: ${attacks[0].title}.`, tone: "attack" };
  }
  if (faults.length) {
    return { text: `No attacks. ${plural(faults.length, "problem")} with the network: ${faults[0].title}.`, tone: "fault" };
  }
  const ruled = report.ruled_out.length;
  return {
    text: ruled ? `No problems found. ${plural(ruled, "thing")} that looked suspicious ${ruled === 1 ? "was" : "were"} checked and ruled out.`
      : "No problems found in this capture.",
    tone: "ok",
  };
}

function Overview({ job, report }: { job: Job; report: Report }) {
  const h = headline(report);
  const start = report.capture.first_ts;
  const tone = { attack: "border-attack/40 bg-attack/5", fault: "border-fault/40 bg-fault/5", ok: "border-benign/40 bg-benign/5" }[h.tone];
  const ToneIcon = h.tone === "ok" ? CheckCircle : Alert;
  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className={`rounded-xl border p-5 ${tone}`}>
        <div className="flex items-start gap-3">
          <ToneIcon size={22} className={`mt-0.5 shrink-0 ${h.tone === "attack" ? "text-attack" : h.tone === "fault" ? "text-fault" : "text-benign"}`} />
          <div>
            <p className="text-[17px] font-semibold leading-snug">{h.text}</p>
            <p className="mt-1 text-muted">
              {num(report.ingest.packets_total)} packets over {duration(report.capture.duration)} from {report.devices} devices,
              analysed in {duration(report.analysis_seconds)}.
            </p>
          </div>
        </div>
      </div>

      {report.quality.map((q) => (
        <div key={q.code} className="flex items-start gap-3 rounded-xl border border-review/40 bg-review/5 p-4">
          <Info size={18} className="mt-0.5 shrink-0 text-review" />
          <div>
            <p className="font-medium">{q.message}</p>
            {q.detail && <p className="mt-0.5 text-[13px] text-muted">{q.detail}</p>}
          </div>
        </div>
      ))}

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <Kpi label="Packets" value={num(report.ingest.packets_total)}
          sub={report.ingest.packets_skipped ? `${num(report.ingest.packets_skipped)} skipped` : "all decoded"} />
        <Kpi label="Duration" value={duration(report.capture.duration)} sub={start ? clock(start) : ""} />
        <Kpi label="Devices" value={String(report.devices)} sub={`${report.hosts} IP addresses`} />
        <Kpi label="Attacks" value={String(report.findings.filter((f) => f.verdict === "attack").length)} tone="text-attack" />
        <Kpi label="Faults" value={String(report.findings.filter((f) => f.verdict === "fault").length)} tone="text-fault" />
        <Kpi label="Ruled out" value={String(report.ruled_out.length)} tone="text-benign" sub="checked, not a problem" />
      </div>

      <div className="card p-4">
        <div className="mb-2 flex items-center justify-between">
          <p className="label">Traffic and findings over time</p>
          <a className="link text-[12px]" href={href(`/a/${job.id}/timeline`)}>Open timeline</a>
        </div>
        <TimelineChart report={report} jobId={job.id} height={110} />
      </div>

      <FindingGroups job={job} report={report} />
      <div className="grid gap-5 lg:grid-cols-2">
        <ProtocolMix report={report} />
        <Inventory report={report} />
      </div>
    </div>
  );
}

// Text taken straight from packets (names, hostnames). The server escaped it, and React renders
// it as plain text, so a hostname like "<script>" is just shown, never run.
function Inventory({ report }: { report: Report }) {
  if (!report.names.length && !report.device_names.length) return null;
  return (
    <div className="card p-4">
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

function Kpi({ label, value, sub, tone }: { label: string; value: string; sub?: string; tone?: string }) {
  return (
    <div className="card px-4 py-3">
      <p className="label">{label}</p>
      <p className={`mt-1 text-[22px] font-semibold tabular-nums leading-tight ${tone && value !== "0" ? tone : ""}`}>{value}</p>
      {sub && <p className="truncate text-[12px] text-muted">{sub}</p>}
    </div>
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
          <p className="label border-b border-line px-4 py-2.5">{g.title}</p>
          <FindingRows job={job} items={g.items} start={report.capture.first_ts} />
        </div>
      ))}
      {report.ruled_out.length > 0 && (
        <div className="card overflow-hidden">
          <button type="button" onClick={() => setOpen(!open)}
            className="flex w-full items-center gap-2 px-4 py-3 text-left hover:bg-raised/50">
            {open ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
            <CheckCircle size={15} className="text-benign" />
            <span className="font-medium">Checked and ruled out</span>
            <span className="text-muted">({report.ruled_out.length}) Looked suspicious, but the evidence says it's normal.</span>
          </button>
          {open && <FindingRows job={job} items={report.ruled_out} start={report.capture.first_ts} />}
        </div>
      )}
    </div>
  );
}

export function FindingRows({ job, items, start, selected }: { job: Job; items: Finding[]; start: number | null;
  selected?: string }) {
  return (
    <ul className="divide-y divide-line">
      {items.map((f) => (
        <li key={f.id}>
          <a href={href(`/a/${job.id}/findings/${f.id}`)}
            className={`flex flex-col gap-2 px-4 py-3 transition-colors hover:bg-raised/60 sm:flex-row sm:items-center sm:gap-4 ${selected === f.id
              ? "bg-raised" : ""}`}>
            <div className="flex min-w-0 flex-1 items-start gap-3">
              <VerdictChip verdict={f.verdict} size="sm" />
              <div className="min-w-0">
                <p className="truncate font-medium">{f.title}</p>
                <div className="mt-1 flex flex-wrap gap-1.5">
                  {f.entities.slice(0, 3).map((e) => <EntityChip key={`${e.kind}-${e.value}-${e.role}`} {...e} />)}
                </div>
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-4 pl-[88px] sm:pl-0">
              <SeverityBadge severity={f.severity} />
              <ConfidenceBar value={f.confidence} verdict={f.verdict} width="w-16" />
              <span className="mono hidden w-20 text-right text-muted lg:block">{offset(f.time_start, start)}</span>
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
  const colours = ["bg-accent", "bg-review", "bg-benign", "bg-fault", "bg-attack/70", "bg-muted", "bg-ink/40"];
  return (
    <div className="card h-fit p-4">
      <p className="label mb-3">Protocol mix</p>
      <div className="flex h-2.5 overflow-hidden rounded-full bg-line">
        {entries.map(([name, n], i) => (
          <span key={name} className={colours[i % colours.length]} style={{ width: `${(n / total) * 100}%` }} title={`${name}: ${num(n)}`} />
        ))}
      </div>
      <ul className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-[12.5px]">
        {entries.map(([name, n], i) => (
          <li key={name} className="flex items-center gap-1.5">
            <span className={`h-2 w-2 rounded-sm ${colours[i % colours.length]}`} />
            {name} <span className="tabular-nums text-muted">{((n / total) * 100).toFixed(1)}%</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function FindingsTab({ job, report, selected }: { job: Job; report: Report; selected?: string }) {
  const all = [...sortFindings(report.findings), ...sortFindings(report.ruled_out)];
  const current = all.find((f) => f.id === selected) ?? all[0];
  if (!all.length) {
    return <div className="card mx-auto max-w-3xl p-8 text-center text-muted">Nothing to report in this capture.</div>;
  }
  return (
    <div className="grid gap-5 xl:grid-cols-[minmax(320px,420px)_1fr]">
      <div className="card h-fit overflow-hidden xl:sticky xl:top-[4.5rem] xl:max-h-[calc(100vh-6rem)] xl:overflow-y-auto">
        <p className="label border-b border-line px-4 py-2.5">Problems ({report.findings.length})</p>
        <CompactRows job={job} items={sortFindings(report.findings)} selected={current?.id} />
        {report.ruled_out.length > 0 && (
          <>
            <p className="label border-y border-line px-4 py-2.5">Checked and ruled out ({report.ruled_out.length})</p>
            <CompactRows job={job} items={sortFindings(report.ruled_out)} selected={current?.id} />
          </>
        )}
      </div>
      {current && <FindingDetail key={current.id} job={job} report={report} finding={current} />}
    </div>
  );
}

function CompactRows({ job, items, selected }: { job: Job; items: Finding[]; selected?: string }) {
  return (
    <ul className="divide-y divide-line">
      {items.map((f) => (
        <li key={f.id}>
          <a href={href(`/a/${job.id}/findings/${f.id}`)}
            className={`block px-4 py-2.5 transition-colors hover:bg-raised/60 ${selected === f.id ? "bg-raised shadow-[inset_3px_0_0_rgb(var(--accent))]" : ""}`}>
            <div className="flex items-center justify-between gap-2">
              <VerdictChip verdict={f.verdict} size="sm" />
              <ConfidenceBar value={f.confidence} verdict={f.verdict} width="w-12" />
            </div>
            <p className="mt-1.5 line-clamp-2 text-[13px] font-medium leading-snug">{f.title}</p>
          </a>
        </li>
      ))}
    </ul>
  );
}
