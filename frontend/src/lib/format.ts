import type { Severity, Verdict } from "./types";

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

export function duration(s: number): string {
  if (s < 1) return `${Math.round(s * 1000)} ms`;
  if (s < 60) return `${s.toFixed(s < 10 ? 1 : 0)} s`;
  const m = Math.floor(s / 60);
  const rest = Math.round(s % 60);
  if (m < 60) return `${m} min ${rest} s`;
  return `${Math.floor(m / 60)} h ${m % 60} min`;
}

export function clock(ts: number): string {
  return new Date(ts * 1000).toISOString().slice(11, 19) + " UTC";
}

export function offset(ts: number, start: number | null): string {
  if (start == null) return "";
  const d = Math.max(0, ts - start);
  const m = Math.floor(d / 60);
  const s = d - m * 60;
  return `+${m}:${s.toFixed(1).padStart(4, "0")}`;
}

export const pct = (x: number) => `${Math.round(x * 100)}%`;

export const num = (n: number) => n.toLocaleString("en-US");

export const VERDICT_LABEL: Record<Verdict, string> = {
  attack: "Attack",
  fault: "Fault",
  needs_review: "Needs review",
  benign: "Ruled out",
};

export const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
