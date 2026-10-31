import type { Job, Sample, ServerConfig } from "./types";

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, { credentials: "same-origin", ...init });
  } catch {
    throw new ApiError("Cannot reach the NetTriage server. Is it still running?", 0);
  }
  if (!res.ok) {
    let detail = `Request failed (${res.status}).`;
    try {
      const body = await res.json();
      if (typeof body?.detail === "string") detail = body.detail;
    } catch {
      /* keep the generic message */
    }
    throw new ApiError(detail, res.status);
  }
  return res.status === 204 ? (undefined as T) : ((await res.json()) as T);
}

// HTTP headers must be plain ASCII; the name is only a label, so anything else is replaced.
const asciiName = (name: string) => name.replace(/[^\x20-\x7e]/g, "_").slice(0, 200) || "capture.pcap";

export const api = {
  config: () => call<ServerConfig>("/api/config"),
  samples: () => call<Sample[]>("/api/samples"),
  upload: (file: File) =>
    call<{ id: string }>("/api/analyses", {
      method: "POST",
      body: file,
      headers: { "content-type": "application/octet-stream", "x-filename": asciiName(file.name) },
    }),
  analyseSample: (name: string) => call<{ id: string }>(`/api/samples/${encodeURIComponent(name)}`, { method: "POST" }),
  job: (id: string) => call<Job>(`/api/analyses/${id}`),
  remove: (id: string) => call<void>(`/api/analyses/${id}`, { method: "DELETE" }),
  evidenceUrl: (id: string, findingId: string) => `/api/analyses/${id}/evidence/${findingId}`,
  reportUrl: (id: string) => `/api/analyses/${id}/report`,
  events: (id: string) => new EventSource(`/api/analyses/${id}/events`),
};
