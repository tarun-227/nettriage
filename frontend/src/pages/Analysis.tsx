import { useEffect, useState } from "react";
import { api, ApiError } from "../lib/api";
import { bytes, num } from "../lib/format";
import { href } from "../lib/router";
import type { Job } from "../lib/types";
import { ArrowLeft, ShieldAlert } from "../components/icons";
import { RadarDish } from "../components/Console";
import { TopBar } from "../components/TopBar";
import { ReportView } from "./Report";

const MIN_PROGRESS_MS = 700; // long enough to read the checks, even for tiny captures

export function Analysis({ id, rest }: { id: string; rest: string[] }) {
  const [job, setJob] = useState<Job | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [shown, setShown] = useState(false);

  useEffect(() => {
    let source: EventSource | null = null;
    let cancelled = false;
    const opened = Date.now();

    async function loadFinal() {
      try {
        const full = await api.job(id);
        const wait = Math.max(0, MIN_PROGRESS_MS - (Date.now() - opened));
        setTimeout(() => {
          if (!cancelled) {
            setJob(full);
            setShown(true);
          }
        }, wait);
      } catch (e) {
        if (!cancelled) setError(e instanceof ApiError ? e.message : "Could not load the analysis.");
      }
    }

    api.job(id).then((j) => {
      if (cancelled) return;
      if (j.status !== "queued" && j.status !== "running") {
        setJob(j);
        setShown(true);
        return;
      }
      setJob(j);
      source = api.events(id);
      source.onmessage = (ev) => {
        const update = JSON.parse(ev.data) as Job;
        setJob((prev) => ({ ...(prev ?? update), ...update }));
        if (update.status !== "queued" && update.status !== "running") {
          source?.close();
          loadFinal();
        }
      };
      source.onerror = () => {
        source?.close();
        loadFinal();
      };
    }).catch((e) => setError(e instanceof ApiError ? e.message : "Could not load the analysis."));

    return () => {
      cancelled = true;
      source?.close();
    };
  }, [id]);

  if (error) return <Problem title="Analysis not found" message={error} />;
  if (!job) return <Shell><p className="text-muted">Loading...</p></Shell>;
  if (job.status === "rejected") {
    return <Problem title="This file was refused" message={job.message} security
      detail="NetTriage checks the file's signature before reading anything. Nothing was parsed, and the upload has
        already been deleted." />;
  }
  if (job.status === "error") return <Problem title="The analysis failed" message={job.message} />;
  if (job.status === "done" && job.report && shown) return <ReportView job={job} report={job.report} rest={rest} />;
  return <Progress job={job} />;
}

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-full flex-col">
      <TopBar />
      <main className="mx-auto flex w-full max-w-2xl flex-1 flex-col justify-center px-4 py-16">{children}</main>
    </div>
  );
}

function Problem({ title, message, detail, security }: { title: string; message: string; detail?: string;
  security?: boolean }) {
  return (
    <Shell>
      <div className="card p-6">
        <div className="flex items-start gap-4">
          <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-full ${security
            ? "bg-benign/10 text-benign" : "bg-attack/10 text-attack"}`}>
            <ShieldAlert size={20} />
          </span>
          <div>
            <h1 className="font-mono text-[17px] font-bold text-white">{title}</h1>
            <p className="mt-2 text-[15px]">{message}</p>
            {detail && <p className="mt-3 text-muted">{detail}</p>}
            <a href={href("/app")} className="btn mt-5"><ArrowLeft size={14} /> Analyse another file</a>
          </div>
        </div>
      </div>
    </Shell>
  );
}

function Progress({ job }: { job: Job }) {
  const p = job.progress ?? {};
  const fraction = p.size ? Math.min(1, (p.bytes ?? 0) / p.size) : 0;
  const reading = job.status === "running" && p.stage === "analyze";
  const explaining = p.stage === "explain" || job.status === "done";
  const steps = [
    { label: "File signature and size checked", done: true },
    { label: "Isolated analysis process started", done: job.status !== "queued", active: job.status === "queued" },
    {
      label: reading ? `Reading packets: ${num(p.packets ?? 0)} so far${p.skipped ? `, ${num(p.skipped)} damaged and skipped` : ""}`
        : "Reading and decoding packets",
      done: explaining, active: job.status === "running" && !explaining,
    },
    { label: "Weighing explanations: fault, attack or normal?", done: job.status === "done", active: explaining },
    { label: "Writing the plain-language report", done: job.status === "done" },
  ];
  return (
    <Shell>
      <RadarDish className="mx-auto -mb-6 w-44" active />
      <div className="card p-6 font-mono">
        <p className="label text-neon">Analysing</p>
        <h1 className="mt-1 truncate text-[16px] font-bold text-white">{job.file_name}</h1>
        <p className="text-[12px] text-muted">{bytes(job.size)}</p>
        <div className="mt-5 h-1.5 overflow-hidden rounded-full bg-line">
          <div className="h-full rounded-full bg-neon shadow-glow transition-all duration-300"
            style={{ width: `${Math.round((explaining ? 1 : Math.max(0.04, fraction)) * 100)}%` }} />
        </div>
        <ol className="mt-5 space-y-2 text-[13px]">
          {steps.map((s) => (
            <li key={s.label} className="flex items-baseline gap-3">
              <span className={`shrink-0 whitespace-pre font-bold ${s.done ? "text-neon" : s.active ? "animate-pulse text-amber" : "text-muted/50"}`}>
                {s.done ? "[ OK ]" : s.active ? "[ >> ]" : "[    ]"}
              </span>
              <span className={s.done || s.active ? "text-ink" : "text-muted"}>{s.label}</span>
            </li>
          ))}
        </ol>
      </div>
    </Shell>
  );
}
