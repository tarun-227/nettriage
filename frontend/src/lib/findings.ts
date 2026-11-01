import { SEVERITY_ORDER } from "./format";
import type { Finding, Report } from "./types";

export function sortFindings(list: Finding[]): Finding[] {
  const order = { attack: 0, fault: 1, needs_review: 2, benign: 3 };
  return [...list].sort((a, b) => order[a.verdict] - order[b.verdict]
    || SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.confidence - a.confidence);
}

// The finding to act on first: the root cause of the most serious incident, else the most serious alert.
export function rootFinding(report: Report): Finding | undefined {
  const incident = report.incidents?.[0];
  const root = incident && report.findings.find((f) => f.id === incident.root_finding);
  return root ?? sortFindings(report.findings)[0];
}

export const firstSentence = (text: string) => {
  const m = /^(.+?[.!?])(\s|$)/.exec(text);
  return m ? m[1] : text;
};
