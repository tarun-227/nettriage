import { offset, num } from "../lib/format";
import { href } from "../lib/router";
import type { Report } from "../lib/types";
import { verdictBg } from "./ui";

// Packet volume as bars, with a marker at the start of every alert. Plain SVG, no chart library.
export function TimelineChart({ report, jobId, height = 120 }: { report: Report; jobId: string; height?: number }) {
  const buckets = report.timeline;
  const start = report.capture.first_ts ?? 0;
  const span = Math.max(report.capture.duration, 1e-6);
  if (!buckets.length) return <p className="py-6 text-center text-muted">No timestamps to plot.</p>;
  const max = Math.max(...buckets.map((b) => b.packets), 1);
  const w = 1000;
  const bw = w / buckets.length;
  const pos = (ts: number) => Math.min(100, Math.max(0, ((ts - start) / span) * 100));
  const markers = report.findings.filter((f) => f.verdict !== "benign");
  return (
    <div>
      <div className="relative" style={{ height }}>
        <svg viewBox={`0 0 ${w} 100`} preserveAspectRatio="none" className="absolute inset-0 h-full w-full"
          role="img" aria-label="Packets per time interval">
          {buckets.map((b, i) => {
            const h = (b.packets / max) * 92;
            return (
              <rect key={i} x={i * bw + bw * 0.12} y={100 - h} width={Math.max(bw * 0.76, 0.5)} height={h}
                className="fill-accent/40">
                <title>{`${offset(b.t, start)}: ${num(b.packets)} packets`}</title>
              </rect>
            );
          })}
        </svg>
        {markers.map((f) => (
          <a key={f.id} href={href(`/a/${jobId}/findings/${f.id}`)} title={f.title}
            className="group absolute top-0 flex h-full -translate-x-1/2 flex-col items-center"
            style={{ left: `${pos(f.time_start)}%` }}>
            <span className={`h-2.5 w-2.5 rounded-full ring-2 ring-surface ${verdictBg[f.verdict]}`} />
            <span className={`w-px flex-1 opacity-60 group-hover:opacity-100 ${verdictBg[f.verdict]}`} />
          </a>
        ))}
      </div>
      <div className="mono mt-1.5 flex justify-between text-[11px] text-muted">
        <span>{offset(start, start)}</span>
        <span>{offset(start + span / 2, start)}</span>
        <span>{offset(start + span, start)}</span>
      </div>
    </div>
  );
}
