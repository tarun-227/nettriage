import { useState } from "react";
import { api } from "../lib/api";
import { clock, offset, pct } from "../lib/format";
import type { Finding, Hypothesis, Job, Report } from "../lib/types";
import { ChevronDown, ChevronRight, Download, Info, Minus, Plus, Wrench } from "../components/icons";
import { CopyButton, EntityChip, Section, SeverityBadge, VerdictChip, verdictBg } from "../components/ui";

export function FindingDetail({ job, report, finding: f }: { job: Job; report: Report; finding: Finding }) {
  const [technical, setTechnical] = useState(false);
  const start = report.capture.first_ts;
  const runnerUp = f.hypotheses[1];
  return (
    <article className="min-w-0 space-y-4">
      <header className="card p-5">
        <div className="flex flex-wrap items-center gap-3">
          <VerdictChip verdict={f.verdict} />
          <SeverityBadge severity={f.severity} />
          <span className="text-[12.5px] text-muted">
            <span className="font-semibold text-ink">{pct(f.confidence)}</span> confident
            {runnerUp && <> · next most likely: {runnerUp.label} ({pct(runnerUp.probability)})</>}
          </span>
        </div>
        <h2 className="mt-3 text-[20px] font-semibold leading-snug">{f.title}</h2>
        <p className="mt-1 text-[12.5px] text-muted">
          {clock(f.time_start)} to {clock(f.time_end)}
          <span className="mono ml-2">({offset(f.time_start, start)} to {offset(f.time_end, start)})</span>
          <span className="ml-2">· {f.analyzer.toUpperCase()} analyser</span>
        </p>

        <div className="mt-4 inline-flex rounded-lg border border-line bg-raised p-0.5 text-[12.5px]" role="tablist">
          {[["Plain language", false], ["Technical", true]].map(([label, value]) => (
            <button key={String(label)} type="button" role="tab" aria-selected={technical === value}
              onClick={() => setTechnical(value as boolean)}
              className={`rounded-md px-3 py-1 font-medium ${technical === value ? "bg-surface text-ink shadow-card" : "text-muted"}`}>
              {label as string}
            </button>
          ))}
        </div>
        <p className="mt-3 max-w-3xl text-[15px] leading-relaxed">{technical ? f.summary_technical : f.summary_simple}</p>
      </header>

      <Section title="Why NetTriage thinks this" icon={<Info size={15} className="text-accent" />}
        right={<span className="text-[12px] text-muted">Every explanation it considered, and the evidence for and against</span>}>
        <ul className="space-y-2">
          {f.hypotheses.map((h, i) => <HypothesisRow key={h.key} h={h} winner={i === 0} />)}
        </ul>
      </Section>

      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="Likely cause" icon={<Info size={15} className="text-muted" />}>
          <p className="leading-relaxed">{f.cause}</p>
        </Section>
        <Section title="What to do" icon={<Wrench size={15} className="text-muted" />}>
          <FixList steps={f.fix_steps} />
        </Section>
      </div>

      <Evidence job={job} finding={f} start={start} />
    </article>
  );
}

function HypothesisRow({ h, winner }: { h: Hypothesis; winner: boolean }) {
  const [open, setOpen] = useState(winner);
  return (
    <li className={`rounded-lg border ${winner ? "border-line bg-raised/50" : "border-line/70"}`}>
      <button type="button" onClick={() => setOpen(!open)} className="flex w-full items-center gap-3 px-3 py-2.5 text-left">
        {open ? <ChevronDown size={14} className="shrink-0 text-muted" /> : <ChevronRight size={14} className="shrink-0 text-muted" />}
        <span className="min-w-0 flex-1">
          <span className="font-medium">{winner ? h.label : `Why not ${h.label}?`}</span>
        </span>
        <VerdictChip verdict={h.verdict} size="sm" />
        <span className="hidden h-1.5 w-28 overflow-hidden rounded-full bg-line sm:block">
          <span className={`block h-full ${verdictBg[h.verdict]}`} style={{ width: pct(h.probability) }} />
        </span>
        <span className="w-10 text-right text-[12.5px] font-semibold tabular-nums">{pct(h.probability)}</span>
      </button>
      {open && (
        <div className="border-t border-line px-3 py-2.5">
          {h.evidence.length === 0 ? (
            <p className="text-[13px] text-muted">No evidence pointed this way; it only had its prior.</p>
          ) : (
            <ul className="space-y-1.5">
              {h.evidence.map((e, i) => (
                <li key={i} className="flex items-start gap-2.5 text-[13px]">
                  <span className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded ${e.weight >= 0
                    ? "bg-accent/15 text-accent" : "bg-attack/10 text-attack/80"}`}
                    title={e.weight >= 0 ? "Supports this explanation" : "Counts against it"}>
                    {e.weight >= 0 ? <Plus size={11} /> : <Minus size={11} />}
                  </span>
                  <span className="flex-1 leading-relaxed">{e.reason}</span>
                  <span className="mono shrink-0 text-[11px] text-muted" title="Log-likelihood weight">
                    {e.weight > 0 ? "+" : ""}{e.weight.toFixed(1)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </li>
  );
}

function FixList({ steps }: { steps: string[] }) {
  const [done, setDone] = useState<boolean[]>(() => steps.map(() => false));
  return (
    <ol className="space-y-2.5">
      {steps.map((s, i) => (
        <li key={i}>
          <label className="flex cursor-pointer items-start gap-2.5">
            <input type="checkbox" checked={done[i]} className="mt-0.5 h-4 w-4 shrink-0 accent-[rgb(var(--accent))]"
              onChange={() => setDone(done.map((d, j) => (j === i ? !d : d)))} />
            <span className={`leading-relaxed ${done[i] ? "text-muted line-through" : ""}`}>{s}</span>
          </label>
        </li>
      ))}
    </ol>
  );
}

function Evidence({ job, finding: f, start }: { job: Job; finding: Finding; start: number | null }) {
  const frames = f.frames.slice(0, 60);
  const frameFilter = frames.length ? `frame.number in {${frames.join(" ")}}` : "";
  return (
    <Section title="Evidence" icon={<Download size={15} className="text-muted" />}
      right={f.has_evidence_pcap ? (
        <a className="btn btn-primary px-2.5 py-1 text-[12px]" href={api.evidenceUrl(job.id, f.id)} download>
          <Download size={13} /> evidence.pcap ({Math.min(f.frames.length, 200)} packets)
        </a>
      ) : undefined}>
      <div className="space-y-4">
        {f.entities.length > 0 && (
          <div>
            <p className="label mb-2">Involved</p>
            <div className="flex flex-wrap gap-1.5">
              {f.entities.map((e) => (
                <span key={`${e.kind}-${e.value}-${e.role}`} className="inline-flex items-center gap-1.5">
                  <EntityChip {...e} />
                  {e.role && <span className="text-[11.5px] text-muted">{e.role}</span>}
                </span>
              ))}
            </div>
          </div>
        )}

        {f.key_packets.length > 0 && (
          <div>
            <p className="label mb-2">Key packets</p>
            <div className="overflow-x-auto rounded-lg border border-line">
              <table className="w-full min-w-[640px] text-left">
                <thead className="bg-raised text-[11.5px] text-muted">
                  <tr>
                    <th className="px-3 py-1.5 font-semibold">No.</th>
                    <th className="px-3 py-1.5 font-semibold">Time</th>
                    <th className="px-3 py-1.5 font-semibold">Source</th>
                    <th className="px-3 py-1.5 font-semibold">Destination</th>
                    <th className="px-3 py-1.5 font-semibold">Protocol</th>
                    <th className="px-3 py-1.5 font-semibold">Info</th>
                  </tr>
                </thead>
                <tbody className="mono divide-y divide-line">
                  {f.key_packets.map((k) => (
                    <tr key={`${k.frame}-${k.summary}`} className="align-top hover:bg-raised/40">
                      <td className="px-3 py-1.5 tabular-nums text-accent">{k.frame}</td>
                      <td className="whitespace-nowrap px-3 py-1.5 text-muted">{offset(k.ts, start)}</td>
                      <td className="whitespace-nowrap px-3 py-1.5">{k.src}</td>
                      <td className="whitespace-nowrap px-3 py-1.5">{k.dst}</td>
                      <td className="px-3 py-1.5">{k.protocol}</td>
                      <td className="min-w-[280px] break-words px-3 py-1.5">{k.summary}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="mt-1.5 text-[12px] text-muted">Frame numbers match Wireshark's "No." column.</p>
          </div>
        )}

        <div className="grid gap-3 md:grid-cols-2">
          <FilterBox label="Show the whole pattern in Wireshark" filter={f.wireshark_filter} />
          {frameFilter && <FilterBox label={`Jump to the ${frames.length} evidence frames`} filter={frameFilter} />}
        </div>
      </div>
    </Section>
  );
}

function FilterBox({ label, filter }: { label: string; filter: string }) {
  return (
    <div className="rounded-lg border border-line bg-raised/40 p-3">
      <div className="mb-1.5 flex items-center justify-between gap-2">
        <p className="text-[12px] text-muted">{label}</p>
        <CopyButton text={filter} label="Copy filter" />
      </div>
      <code className="mono block break-all text-[12px]">{filter}</code>
    </div>
  );
}
