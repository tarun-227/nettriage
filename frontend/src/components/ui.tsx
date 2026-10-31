import { useState, type ReactNode } from "react";
import { VERDICT_LABEL, pct } from "../lib/format";
import type { Severity, Verdict } from "../lib/types";
import { CheckCircle, Copy, HelpCircle, ShieldAlert, Wrench, Check } from "./icons";

// Verdicts are told apart by colour, icon and text together, never colour alone.
const VERDICT_STYLE: Record<Verdict, { cls: string; Icon: typeof ShieldAlert }> = {
  attack: { cls: "bg-attack/10 text-attack border-attack/35", Icon: ShieldAlert },
  fault: { cls: "bg-fault/10 text-fault border-fault/35", Icon: Wrench },
  needs_review: { cls: "bg-review/10 text-review border-review/35", Icon: HelpCircle },
  benign: { cls: "bg-benign/10 text-benign border-benign/35", Icon: CheckCircle },
};

export function VerdictChip({ verdict, size = "md" }: { verdict: Verdict; size?: "sm" | "md" }) {
  const { cls, Icon } = VERDICT_STYLE[verdict];
  const pad = size === "sm" ? "px-1.5 py-0.5 text-[11px]" : "px-2 py-0.5 text-[12px]";
  return (
    <span className={`inline-flex shrink-0 items-center gap-1 rounded-md border font-semibold ${pad} ${cls}`}>
      <Icon size={size === "sm" ? 12 : 13} />
      {VERDICT_LABEL[verdict]}
    </span>
  );
}

export const verdictText: Record<Verdict, string> = {
  attack: "text-attack",
  fault: "text-fault",
  needs_review: "text-review",
  benign: "text-benign",
};
export const verdictBg: Record<Verdict, string> = {
  attack: "bg-attack",
  fault: "bg-fault",
  needs_review: "bg-review",
  benign: "bg-benign",
};

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: "text-attack",
  high: "text-attack/80",
  medium: "text-fault",
  low: "text-muted",
  info: "text-muted",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  const bars = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[severity];
  return (
    <span className={`inline-flex items-center gap-1.5 text-[12px] font-medium capitalize ${SEVERITY_STYLE[severity]}`}
      title={`Severity: ${severity}`}>
      <span className="flex items-end gap-[2px]" aria-hidden="true">
        {[1, 2, 3, 4].map((i) => (
          <span key={i} className={`w-[3px] rounded-sm ${i <= bars ? "bg-current" : "bg-line"}`}
            style={{ height: `${4 + i * 2.5}px` }} />
        ))}
      </span>
      {severity}
    </span>
  );
}

export function ConfidenceBar({ value, verdict, width = "w-20" }: { value: number; verdict: Verdict; width?: string }) {
  return (
    <span className="inline-flex items-center gap-2" title={`Confidence ${pct(value)}`}>
      <span className={`h-1.5 ${width} overflow-hidden rounded-full bg-line`}>
        <span className={`block h-full rounded-full ${verdictBg[verdict]}`} style={{ width: pct(value) }} />
      </span>
      <span className="w-9 text-right tabular-nums text-[12px] text-muted">{pct(value)}</span>
    </span>
  );
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button type="button" className="btn px-2 py-1 text-[12px]"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        } catch {
          /* clipboard unavailable; the text stays selectable */
        }
      }}>
      {done ? <Check size={13} /> : <Copy size={13} />}
      {done ? "Copied" : label}
    </button>
  );
}

export function Section({ title, icon, children, right }: {
  title: string;
  icon?: ReactNode;
  children: ReactNode;
  right?: ReactNode;
}) {
  return (
    <section className="card">
      <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-2.5">
        <h3 className="flex items-center gap-2 text-[13px] font-semibold">
          {icon}
          {title}
        </h3>
        {right}
      </header>
      <div className="p-4">{children}</div>
    </section>
  );
}

export function EntityChip({ kind, value, role }: { kind: string; value: string; role?: string | null }) {
  return (
    <span className="inline-flex max-w-full items-center gap-1 rounded-md border border-line bg-raised px-1.5 py-0.5"
      title={role ? `${role} (${kind})` : kind}>
      <span className="text-[10px] font-semibold uppercase text-muted">{kind}</span>
      <span className="mono truncate">{value}</span>
    </span>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-6 text-center text-muted">{children}</p>;
}
