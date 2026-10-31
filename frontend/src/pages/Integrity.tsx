import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { bytes, clock, duration, num } from "../lib/format";
import type { Job, Report, ServerConfig } from "../lib/types";
import { Check, Cpu, Fingerprint, Lock, Trash, WifiOff, X } from "../components/icons";
import { CopyButton, Section } from "../components/ui";

// The "security receipt": what was checked, what was skipped and why, and what happened to the upload.
export function IntegrityTab({ job, report }: { job: Job; report: Report }) {
  const [config, setConfig] = useState<ServerConfig | null>(null);
  useEffect(() => {
    api.config().then(setConfig).catch(() => setConfig(null));
  }, []);
  const ing = report.ingest;
  const reasons = Object.entries(ing.skip_reasons).sort((a, b) => b[1] - a[1]);
  const uploaded = job.upload_deleted_at != null;
  const guarantees = [
    { ok: true, Icon: Fingerprint, title: "Signature checked before parsing",
      text: `Recognised as ${ing.format} from its first bytes; anything else is refused unread.` },
    { ok: true, Icon: Cpu, title: "Analysed in an isolated process",
      text: `Its own process, killed if it runs past ${config ? duration(config.max_analysis_seconds) : "the time limit"}.` },
    { ok: true, Icon: WifiOff, title: "No network access",
      text: "NetTriage makes no outbound connections; nothing about this capture left the computer." },
    uploaded
      ? { ok: true, Icon: Trash, title: "Upload deleted", text: `Removed at ${clock(job.upload_deleted_at!)}, right after analysis.` }
      : { ok: true, Icon: Lock, title: "Bundled sample", text: "Analysed in place from the samples folder; nothing was uploaded." },
  ];
  return (
    <div className="mx-auto max-w-6xl space-y-4">
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        {guarantees.map(({ Icon, title, text }) => (
          <div key={title} className="card flex gap-3 p-4">
            <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-benign/10 text-benign">
              <Icon size={16} />
            </span>
            <div>
              <p className="font-medium">{title}</p>
              <p className="mt-0.5 text-[12.5px] leading-relaxed text-muted">{text}</p>
            </div>
          </div>
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="File">
          <dl className="grid grid-cols-[130px_1fr] gap-x-4 gap-y-2 text-[13px]">
            <dt className="text-muted">Name</dt><dd className="break-all">{report.capture.file_name}</dd>
            <dt className="text-muted">Size</dt><dd>{bytes(report.capture.size_bytes)}</dd>
            <dt className="text-muted">Format</dt><dd>{ing.format} · {ing.link_types.join(", ") || "unknown link type"}</dd>
            <dt className="text-muted">SHA-256</dt>
            <dd className="flex items-start gap-2">
              <code className="mono break-all text-[12px]">{report.capture.sha256}</code>
              <CopyButton text={report.capture.sha256} label="Copy" />
            </dd>
            <dt className="text-muted">Packets</dt>
            <dd>{num(ing.packets_total)} read, {num(ing.packets_decoded)} decoded, {num(ing.packets_skipped)} skipped</dd>
            <dt className="text-muted">Analysis time</dt><dd>{duration(report.analysis_seconds)}</dd>
          </dl>
        </Section>

        <Section title="Checks">
          <ul className="space-y-2">
            {report.integrity.map((c) => (
              <li key={c.name} className="flex items-start gap-2.5">
                <span className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full ${c.passed
                  ? "bg-benign/15 text-benign" : "bg-fault/15 text-fault"}`}>
                  {c.passed ? <Check size={12} /> : <X size={12} />}
                </span>
                <span><span className="font-medium">{c.name}</span> <span className="text-muted">· {c.detail}</span></span>
              </li>
            ))}
            {ing.state_caps_hit.map((s) => (
              <li key={s} className="flex items-start gap-2.5 text-fault">
                <X size={14} className="mt-0.5" /> Memory limit reached for the {s}; the oldest entries were summarised.
              </li>
            ))}
          </ul>
        </Section>
      </div>

      <Section title="Skipped packets" right={<span className="text-[12px] text-muted">Damaged packets are isolated, never fatal</span>}>
        {ing.stopped_early && (
          <p className="mb-3 rounded-lg border border-fault/40 bg-fault/5 px-3 py-2 text-[13px]">
            <span className="font-medium text-fault">Reading stopped early.</span> {ing.stop_reason} Everything
            before that point was analysed.
          </p>
        )}
        {reasons.length === 0 ? (
          <p className="text-muted">Every packet decoded cleanly.</p>
        ) : (
          <div className="grid gap-4 md:grid-cols-2">
            <table className="w-full text-[13px]">
              <thead className="text-left text-[11.5px] text-muted"><tr><th className="pb-1.5">Reason</th><th className="pb-1.5 text-right">Packets</th></tr></thead>
              <tbody className="divide-y divide-line">
                {reasons.map(([r, n]) => (
                  <tr key={r}><td className="py-1.5">{r}</td><td className="py-1.5 text-right tabular-nums">{num(n)}</td></tr>
                ))}
              </tbody>
            </table>
            <div>
              <p className="label mb-1.5">Examples</p>
              <ul className="mono max-h-48 space-y-1 overflow-y-auto text-[12px]">
                {ing.skip_examples.map((e) => (
                  <li key={`${e.frame}-${e.reason}`}><span className="text-accent">frame {e.frame}</span> <span className="text-muted">{e.reason}</span></li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </Section>

      {config && (
        <Section title="Limits in force">
          <ul className="grid gap-2 text-[13px] sm:grid-cols-2 lg:grid-cols-4">
            <li><span className="text-muted">Largest upload</span><br />{bytes(config.max_upload_bytes)}</li>
            <li><span className="text-muted">Most packets read</span><br />{num(config.max_packets)}</li>
            <li><span className="text-muted">Longest analysis</span><br />{duration(config.max_analysis_seconds)}</li>
            <li><span className="text-muted">Reports kept for</span><br />{config.retention_minutes} minutes, in memory only</li>
          </ul>
        </Section>
      )}
    </div>
  );
}
