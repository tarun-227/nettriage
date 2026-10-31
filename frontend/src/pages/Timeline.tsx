import { clock, offset } from "../lib/format";
import { href } from "../lib/router";
import type { Job, Report } from "../lib/types";
import { TimelineChart } from "../components/TimelineChart";
import { VerdictChip, verdictBg } from "../components/ui";
import { sortFindings } from "./Report";

// One lane per finding, laid out on the same time axis as the traffic chart.
export function TimelineTab({ job, report }: { job: Job; report: Report }) {
  const start = report.capture.first_ts ?? 0;
  const span = Math.max(report.capture.duration, 1e-6);
  const lanes = [...sortFindings(report.findings), ...sortFindings(report.ruled_out)];
  const left = (ts: number) => Math.min(100, Math.max(0, ((ts - start) / span) * 100));
  return (
    <div className="mx-auto max-w-6xl space-y-4">
      <div className="card p-4">
        <div className="mb-2 flex flex-wrap items-baseline justify-between gap-2">
          <p className="label">Traffic</p>
          <p className="text-[12px] text-muted">{clock(start)} to {clock(start + span)}</p>
        </div>
        <TimelineChart report={report} jobId={job.id} height={150} />
      </div>
      <div className="card overflow-hidden">
        <p className="label border-b border-line px-4 py-2.5">What happened when</p>
        {lanes.length === 0 && <p className="p-6 text-center text-muted">No findings to place on the timeline.</p>}
        <ul className="divide-y divide-line">
          {lanes.map((f) => {
            const l = left(f.time_start);
            const w = Math.max(0.8, left(f.time_end) - l);
            return (
              <li key={f.id}>
                <a href={href(`/a/${job.id}/findings/${f.id}`)}
                  className="grid grid-cols-1 items-center gap-2 px-4 py-2.5 hover:bg-raised/50 md:grid-cols-[300px_1fr]">
                  <span className="flex min-w-0 items-center gap-2">
                    <VerdictChip verdict={f.verdict} size="sm" />
                    <span className="truncate text-[13px]">{f.title}</span>
                  </span>
                  <span className="relative h-5 rounded bg-raised">
                    <span className={`absolute top-1 h-3 rounded ${verdictBg[f.verdict]} ${f.verdict === "benign" ? "opacity-50" : "opacity-85"}`}
                      style={{ left: `${l}%`, width: `${Math.min(w, 100 - l)}%` }}
                      title={`${offset(f.time_start, start)} to ${offset(f.time_end, start)}`} />
                  </span>
                </a>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}
