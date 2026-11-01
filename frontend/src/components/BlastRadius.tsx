// "What the attacker could see": the conversations that passed through an interceptor, and what each exposed.
// Everything here comes from packets the server proved were relayed; nothing is read out of their contents.
import { useState } from "react";
import { num, offset } from "../lib/format";
import type { ExposedFlow, Exposure } from "../lib/types";
import { ChevronDown, ShieldAlert } from "./icons";

function badge(f: ExposedFlow) {
  if (f.service === "DNS") return { text: "Names visible", cls: "border-fault/45 bg-fault/10 text-fault" };
  if (f.encrypted) return { text: "Contents private", cls: "border-benign/45 bg-benign/10 text-benign" };
  if (f.encrypted === false) return { text: "Fully readable", cls: "border-attack/50 bg-attack/10 text-attack" };
  return { text: "Maybe readable", cls: "border-fault/45 bg-fault/10 text-fault" };
}

export function BlastRadius({ exposure: e, start }: { exposure: Exposure; start: number | null }) {
  const [all, setAll] = useState(false);
  const flows = all ? e.flows : e.flows.slice(0, 6);
  const stats = [
    { value: e.readable, label: "read in full", tone: "text-attack" },
    { value: e.metadata_only, label: "server seen, contents private", tone: "text-benign" },
    { value: e.hijacked_names.length, label: "names sent to a fake address", tone: "text-fault" },
  ];
  return (
    <section id="blast" className="scroll-mt-24 overflow-hidden rounded-[18px] border border-attack/40 bg-surface shadow-card">
      <header className="flex flex-wrap items-start justify-between gap-3 border-b border-line px-[22px] py-[18px]">
        <div className="min-w-0 flex-1 basis-[420px]">
          <h2 className="flex items-center gap-2.5 text-[16px] font-semibold text-white">
            <span className="text-attack"><ShieldAlert size={17} /></span> What the attacker could see
          </h2>
          <p className="mt-1.5 max-w-[760px] text-[13.5px] leading-relaxed text-muted">{e.summary}</p>
        </div>
        <span className="font-mono text-[12px] text-muted">{offset(e.start, start)} → {offset(e.end, start)} · {num(e.relayed_packets)} packets relayed</span>
      </header>

      <div className="grid gap-px bg-line sm:grid-cols-3">
        {stats.map((s) => (
          <div key={s.label} className="bg-surface px-[22px] py-4">
            <p className={`glow-text font-mono text-[28px] font-bold leading-none ${s.value ? s.tone : "text-muted"}`}>{s.value}</p>
            <p className="mt-1.5 text-[12.5px] text-muted">{s.label}</p>
          </div>
        ))}
      </div>

      <ul className="border-t border-line">
        {flows.map((f) => {
          const b = badge(f);
          return (
            <li key={`${f.victim}-${f.peer}-${f.protocol}-${f.port}`}
              className="nt-row flex flex-wrap items-center gap-x-4 gap-y-1.5 border-b border-line px-[22px] py-3 last:border-b-0">
              <span className={`w-[140px] shrink-0 whitespace-nowrap rounded-full border px-2.5 py-0.5 text-center font-mono text-[11px] font-semibold ${b.cls}`}>{b.text}</span>
              <span className="min-w-0 flex-1 basis-[220px]">
                <span className="block truncate font-medium text-white">{f.name ?? f.peer}</span>
                <span className="font-mono text-[11.5px] text-muted">
                  {f.victim} → {f.peer}{f.port ? `:${f.port}` : ""}
                </span>
              </span>
              <span className="w-24 font-mono text-[12.5px]">{f.service}</span>
              <span className="w-24 text-right font-mono text-[12px] text-muted">{num(f.packets)} packets</span>
            </li>
          );
        })}
      </ul>
      {e.flows.length > 6 && (
        <button type="button" onClick={() => setAll(!all)} aria-expanded={all}
          className="nt-toggle flex w-full items-center justify-center gap-1.5 border-t border-line py-2.5 font-mono text-[12.5px] text-muted">
          {all ? "Show fewer" : `Show all ${e.flows.length}`}
          <span className={`inline-block transition-transform ${all ? "rotate-180" : ""}`}><ChevronDown size={14} /></span>
        </button>
      )}

      {e.fix_steps.length > 0 && (
        <div className="border-t border-line bg-bg/40 px-[22px] py-4">
          <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.16em] text-attack">Because of this</p>
          <ul className="mt-2.5 flex flex-col gap-2 text-[13.5px] leading-relaxed">
            {e.fix_steps.map((s) => <li key={s} className="flex gap-2.5"><span className="shrink-0 text-attack">▸</span>{s}</li>)}
          </ul>
        </div>
      )}
    </section>
  );
}
