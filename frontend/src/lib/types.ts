// Mirrors backend/nettriage/schema.py. Every string that came from a packet has been
// escaped by the server; React renders all of it as text, never as HTML.

export type Verdict = "attack" | "fault" | "benign" | "needs_review";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface EvidenceItem {
  reason: string;
  weight: number;
  frames: number[];
}

export interface Hypothesis {
  key: string;
  label: string;
  verdict: Verdict;
  probability: number;
  evidence: EvidenceItem[];
}

export interface Entity {
  kind: string;
  value: string;
  role: string | null;
}

export interface KeyPacket {
  frame: number;
  ts: number;
  src: string;
  dst: string;
  protocol: string;
  summary: string;
}

export interface Finding {
  id: string;
  analyzer: string;
  kind: string;
  title: string;
  verdict: Verdict;
  confidence: number;
  margin: number;
  severity: Severity;
  summary_simple: string;
  summary_technical: string;
  cause: string;
  fix_steps: string[];
  hypotheses: Hypothesis[];
  entities: Entity[];
  time_start: number;
  time_end: number;
  frames: number[];
  key_packets: KeyPacket[];
  wireshark_filter: string;
  has_evidence_pcap: boolean;
}

export interface Report {
  schema_version: string;
  capture: {
    file_name: string;
    sha256: string;
    size_bytes: number;
    first_ts: number | null;
    last_ts: number | null;
    duration: number;
  };
  ingest: {
    format: string;
    link_types: string[];
    packets_total: number;
    packets_decoded: number;
    packets_skipped: number;
    skip_reasons: Record<string, number>;
    skip_examples: { frame: number; reason: string }[];
    stopped_early: boolean;
    stop_reason: string | null;
    state_caps_hit: string[];
  };
  integrity: { name: string; passed: boolean; detail: string }[];
  quality: { code: string; message: string; detail: string }[];
  findings: Finding[];
  ruled_out: Finding[];
  hosts: number;
  devices: number;
  protocols: Record<string, number>;
  timeline: { t: number; packets: number; bytes: number }[];
  names: { name: string; count: number }[];
  device_names: { mac: string; hostname: string | null; vendor_class: string | null; ip: string | null }[];
  analysis_seconds: number;
}

export type JobStatus = "queued" | "running" | "done" | "rejected" | "error";

export interface Job {
  id: string;
  file_name: string;
  size: number;
  status: JobStatus;
  message: string;
  progress: { stage?: string; packets?: number; skipped?: number; bytes?: number; size?: number };
  created: number;
  upload_deleted_at: number | null;
  report?: Report;
}

export interface Sample {
  name: string;
  title: string;
  description: string;
  category: "attack" | "fault" | "negative" | "mixed" | "malicious" | string;
  size: number;
}

export interface ServerConfig {
  version: string;
  max_upload_bytes: number;
  max_packets: number;
  max_analysis_seconds: number;
  retention_minutes: number;
  offline: boolean;
  accepted_extensions: string[];
}
