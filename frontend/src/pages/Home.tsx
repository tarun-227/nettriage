import { useEffect, useRef, useState, type DragEvent } from "react";
import { api, ApiError } from "../lib/api";
import { bytes } from "../lib/format";
import { navigate } from "../lib/router";
import type { Sample, ServerConfig } from "../lib/types";
import { Cpu, FileIcon, Fingerprint, ShieldAlert, Trash, Upload, WifiOff, X } from "../components/icons";
import { TopBar } from "../components/TopBar";

const GROUPS: { key: string; title: string; blurb: string }[] = [
  { key: "attack", title: "Attacks", blurb: "Someone is doing this on purpose." },
  { key: "fault", title: "Faults", blurb: "Something is broken or misconfigured." },
  { key: "mixed", title: "Mixed", blurb: "A fault and an attack in the same capture." },
  { key: "negative", title: "Look-alikes", blurb: "Looks suspicious, but is normal. Should raise no alarms." },
  { key: "malicious", title: "Hostile files", blurb: "Broken or booby-trapped captures, handled safely." },
];

export function Home() {
  const [config, setConfig] = useState<ServerConfig | null>(null);
  const [samples, setSamples] = useState<Sample[]>([]);
  const [error, setError] = useState<{ text: string; refused: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [group, setGroup] = useState("attack");
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    api.config().then(setConfig).catch(() => setConfig(null));
    api.samples().then(setSamples).catch(() => setSamples([]));
  }, []);

  async function start(run: () => Promise<{ id: string }>) {
    setBusy(true);
    setError(null);
    try {
      const { id } = await run();
      navigate(`/a/${id}`);
    } catch (e) {
      setError(e instanceof ApiError ? { text: e.message, refused: e.status === 413 || e.status === 415 } : { text: "Something went wrong.", refused: false });
      setBusy(false);
    }
  }

  function pick(file: File | undefined) {
    if (!file) return;
    if (config && file.size > config.max_upload_bytes) {
      setError({ text: `That file is ${bytes(file.size)}; the limit is ${bytes(config.max_upload_bytes)}.`, refused: true });
      return;
    }
    start(() => api.upload(file));
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setDragging(false);
    pick(e.dataTransfer.files?.[0]);
  }

  const shown = samples.filter((s) => s.category === group);
  const limit = config ? bytes(config.max_upload_bytes) : "500 MB";

  return (
    <div className="flex min-h-full flex-col">
      <TopBar />
      <main className="mx-auto w-full max-w-6xl flex-1 px-4 pb-16 pt-10 sm:px-6">
        <div className="mb-8 max-w-3xl">
          <h1 className="text-[28px] font-semibold leading-tight tracking-tight sm:text-[34px]">
            Is your network broken, or is someone breaking it?
          </h1>
          <p className="mt-3 text-[15px] leading-relaxed text-muted">
            Drop in a packet capture. NetTriage finds the faults and attacks in it, tells you which is which and how
            sure it is, explains them in plain language, and points to the exact packets behind every conclusion.
          </p>
        </div>

        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          className={`card flex flex-col items-center justify-center gap-4 border-2 border-dashed px-6 py-12 text-center
            transition-colors ${dragging ? "border-accent bg-accent/5" : "border-line"}`}>
          <div className="flex h-12 w-12 items-center justify-center rounded-full bg-accent/10 text-accent">
            <Upload size={22} />
          </div>
          <div>
            <p className="text-[16px] font-medium">Drop a .pcap or .pcapng file here</p>
            <p className="mt-1 text-muted">Up to {limit}. Wireshark and tcpdump captures both work.</p>
          </div>
          <button type="button" className="btn btn-primary" disabled={busy} onClick={() => input.current?.click()}>
            <FileIcon size={15} />
            {busy ? "Starting..." : "Choose a file"}
          </button>
          <input ref={input} type="file" accept=".pcap,.pcapng,.cap" className="hidden"
            onChange={(e) => pick(e.target.files?.[0])} />
        </div>
        {error && (
          <div role="alert" className="fixed inset-x-0 bottom-6 z-30 mx-auto flex w-[min(640px,calc(100%-2rem))] items-start
            gap-3 rounded-xl border border-benign/40 bg-surface p-4 shadow-2xl">
            <ShieldAlert size={20} className="mt-0.5 shrink-0 text-benign" />
            <div className="flex-1">
              <p className="font-semibold">{error.refused ? "File refused" : "Could not start the analysis"}</p>
              <p className="mt-0.5 text-[13.5px]">{error.text}</p>
              {error.refused && <p className="mt-1 text-[12.5px] text-muted">Nothing was parsed, and nothing was kept.</p>}
            </div>
            <button type="button" className="btn px-2" onClick={() => setError(null)} aria-label="Dismiss"><X size={14} /></button>
          </div>
        )}

        <ul className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { Icon: WifiOff, title: "Never leaves this computer", text: "Works fully offline. No cloud, no telemetry." },
            { Icon: Trash, title: "Upload deleted after analysis", text: "Only the report is kept, in memory, briefly." },
            { Icon: Fingerprint, title: "Checked before it is parsed", text: "Disguised and oversized files are refused." },
            { Icon: Cpu, title: "Isolated, time-limited", text: "Each capture is analysed in a separate process." },
          ].map(({ Icon, title, text }) => (
            <li key={title} className="flex gap-3 rounded-xl border border-line bg-surface/60 p-3">
              <Icon size={18} className="mt-0.5 shrink-0 text-benign" />
              <div>
                <p className="font-medium">{title}</p>
                <p className="text-[12.5px] text-muted">{text}</p>
              </div>
            </li>
          ))}
        </ul>

        {samples.length > 0 && (
          <section className="mt-12">
            <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
              <div>
                <h2 className="text-[18px] font-semibold">No capture at hand? Try a sample</h2>
                <p className="text-muted">Labelled, simulated captures of a small office network. Click one to analyse it.</p>
              </div>
              <div role="tablist" className="flex flex-wrap gap-1 rounded-lg border border-line bg-surface p-1">
                {GROUPS.filter((g) => samples.some((s) => s.category === g.key)).map((g) => (
                  <button key={g.key} role="tab" aria-selected={group === g.key} type="button"
                    onClick={() => setGroup(g.key)}
                    className={`rounded-md px-3 py-1 text-[13px] font-medium transition-colors ${group === g.key
                      ? "bg-raised text-ink" : "text-muted hover:text-ink"}`}>
                    {g.title}
                    <span className="ml-1.5 text-muted">{samples.filter((s) => s.category === g.key).length}</span>
                  </button>
                ))}
              </div>
            </div>
            <p className="mb-3 text-[13px] text-muted">{GROUPS.find((g) => g.key === group)?.blurb}</p>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {shown.map((s) => (
                <button key={s.name} type="button" disabled={busy} onClick={() => start(() => api.analyseSample(s.name))}
                  className="card group flex flex-col gap-1.5 p-4 text-left transition-colors hover:border-accent/50">
                  <span className="flex items-start justify-between gap-2">
                    <span className="font-medium group-hover:text-accent">{s.title}</span>
                    <span className="shrink-0 text-[12px] text-muted">{bytes(s.size)}</span>
                  </span>
                  <span className="line-clamp-3 text-[12.5px] leading-relaxed text-muted">{s.description}</span>
                  <span className="mono mt-auto pt-1 text-[11.5px] text-muted/80">{s.name}</span>
                </button>
              ))}
            </div>
          </section>
        )}
      </main>
      <footer className="border-t border-line py-4 text-center text-[12px] text-muted">
        NetTriage {config?.version ?? ""} · runs locally · results kept for {config?.retention_minutes ?? 60} minutes
      </footer>
    </div>
  );
}
