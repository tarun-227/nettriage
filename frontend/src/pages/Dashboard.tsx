// The working app: start an analysis (upload or a library sample), and revisit this session's reports.
import { useEffect, useMemo, useRef, useState, type DragEvent, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from "react";
import { api, ApiError } from "../lib/api";
import { bytes, num } from "../lib/format";
import { useTitle } from "../lib/live";
import { forgetRecent, listRecent, type Recent } from "../lib/recent";
import { href, navigate } from "../lib/router";
import type { Sample, ServerConfig } from "../lib/types";
import { RadarDish } from "../components/Console";
import { Activity, CheckCircle, Download, FileIcon, Fingerprint, List, Lock, Plus, ShieldAlert, Trash, Upload, WifiOff, X } from "../components/icons";
import { VerifyPackDialog } from "../components/ProofPack";
import { VerdictChip } from "../components/ui";

export const CATEGORIES: Record<string, { label: string; chip: string }> = {
  attack: { label: "Attack", chip: "bg-attack/[0.12] text-attack" },
  fault: { label: "Fault", chip: "bg-fault/[0.12] text-fault" },
  mixed: { label: "Mixed", chip: "bg-review/[0.12] text-review" },
  negative: { label: "Look-alike", chip: "bg-benign/[0.12] text-benign" },
  malicious: { label: "Hostile", chip: "bg-ink/[0.08] text-ink" },
};
const FILTERS = [
  { key: "all", label: "All" }, { key: "attack", label: "Attacks" }, { key: "fault", label: "Faults" },
  { key: "mixed", label: "Mixed" }, { key: "negative", label: "Look-alikes" }, { key: "malicious", label: "Hostile files" },
];

type Problem = { text: string; refused: boolean };
type Tab = "upload" | "library";

function ago(at: number) {
  const s = (Date.now() - at) / 1000;
  if (s < 60) return "just now";
  const m = Math.round(s / 60);
  return m < 60 ? `${m} min ago` : `${Math.floor(m / 60)} h ago`;
}

export function Dashboard({ openNew }: { openNew: boolean }) {
  const [config, setConfig] = useState<ServerConfig | null>(null);
  const [samples, setSamples] = useState<Sample[]>([]);
  const [recent, setRecent] = useState<Recent[]>(listRecent);
  const [modal, setModal] = useState<Tab | null>(openNew ? "upload" : null);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Problem | null>(null);
  const [over, setOver] = useState(false);
  const [checking, setChecking] = useState(false);
  const search = useRef<HTMLInputElement>(null);
  useTitle(modal ? "New analysis · NetTriage" : "Dashboard · NetTriage");

  useEffect(() => {
    api.config().then(setConfig).catch(() => setConfig(null));
    api.samples().then(setSamples).catch(() => setSamples([]));
    // Reports live on the server for a limited time: drop the ones it has already forgotten.
    listRecent().forEach((r) => {
      api.job(r.id).catch((e) => {
        if (e instanceof ApiError && e.status === 404) {
          forgetRecent(r.id);
          setRecent(listRecent());
        }
      });
    });
  }, []);

  useEffect(() => { if (openNew) setModal("upload"); }, [openNew]);

  const closeModal = () => {
    setModal(null);
    setError(null);
    if (openNew) navigate("/app");
  };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const typing = e.target instanceof Element && e.target.closest("input, textarea, [contenteditable]");
      if (e.key === "Escape" && modal) closeModal();
      if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
      if (e.key === "/") { e.preventDefault(); search.current?.focus(); }
      if (e.key.toLowerCase() === "u" && !modal) setModal("upload");
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  async function start(run: () => Promise<{ id: string }>) {
    setBusy(true);
    setError(null);
    try {
      const { id } = await run();
      navigate(`/a/${id}`);
      window.scrollTo({ top: 0 });
    } catch (e) {
      setError(e instanceof ApiError ? { text: e.message, refused: e.status === 413 || e.status === 415 }
        : { text: "Something went wrong.", refused: false });
      setBusy(false);
    }
  }

  function upload(file: File) {
    if (config && file.size > config.max_upload_bytes) {
      setError({ text: `That file is ${bytes(file.size)}; the limit is ${bytes(config.max_upload_bytes)}.`, refused: true });
      return;
    }
    start(() => api.upload(file));
  }
  const runSample = (name: string) => start(() => api.analyseSample(name));

  async function remove(id: string) {
    forgetRecent(id);
    setRecent(listRecent());
    try { await api.remove(id); } catch { /* already gone */ }
  }

  const q = query.trim().toLowerCase();
  const matches = (s: string) => !q || s.toLowerCase().includes(q);
  const library = samples.filter((s) => (filter === "all" || s.category === filter) && (matches(s.title) || matches(s.name)));
  const shownRecent = recent.filter((r) => matches(r.name));
  const totals = useMemo(() => ({
    attacks: recent.reduce((n, r) => n + r.attacks, 0),
    faults: recent.reduce((n, r) => n + r.faults, 0),
    clean: recent.filter((r) => !r.attacks && !r.faults).length,
  }), [recent]);
  const limit = config ? bytes(config.max_upload_bytes) : "500 MB";

  const dropProps = {
    onDragOver: (e: DragEvent) => { e.preventDefault(); setOver(true); },
    onDragLeave: () => setOver(false),
    onDrop: (e: DragEvent) => { e.preventDefault(); setOver(false); const f = e.dataTransfer.files?.[0]; if (f) upload(f); },
  };

  return (
    <div className="flex min-h-full bg-bg">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col gap-6 border-r border-line bg-surface px-3.5 py-5 md:flex">
        <a href={href("/")} className="flex items-center gap-2.5 px-2 py-1 font-mono text-[13px] font-bold tracking-[0.22em] text-neon">
          <span className="h-2 w-2 animate-pulse rounded-full bg-neon shadow-glow" /> NETTRIAGE
        </a>
        <nav aria-label="App" className="flex flex-col gap-0.5 text-[13.5px] font-medium">
          <span className="flex items-center gap-2.5 rounded-lg bg-neon/10 px-2.5 py-2 text-neon shadow-[inset_2px_0_0_rgb(var(--neon))]"><Activity size={16} /> Dashboard</span>
          <NavButton target="recent" icon={<List size={16} />} label="Analyses" count={recent.length} />
          <NavButton target="library" icon={<FileIcon size={16} />} label="Library" count={samples.length} />
          <button type="button" onClick={() => setChecking(true)} className="nt-nav flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-muted">
            <Fingerprint size={16} /> Check a Proof Pack
          </button>
          <a href={href("/")} className="nt-nav flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-muted"><Lock size={16} /> How it works</a>
        </nav>
        <div className="mt-auto flex flex-col gap-2 rounded-xl border border-line bg-bg p-3.5">
          <span className="inline-flex items-center gap-1.5 self-start rounded border border-neon/40 px-2 py-0.5 font-mono text-[11px] tracking-[0.16em] text-neon">
            <WifiOff size={12} /> OFFLINE
          </span>
          <p className="text-[12.5px] leading-normal text-muted">
            Uploads are deleted after analysis. Reports are kept for {config?.retention_minutes ?? 60} minutes.
          </p>
        </div>
      </aside>

      <div className="min-w-0 flex-1">
        <header className="flex flex-wrap items-center gap-4 border-b border-line px-4 py-4 sm:px-8 sm:py-5">
          <a href={href("/")} className="flex items-center gap-2 font-mono text-[12px] font-bold tracking-[0.22em] text-neon md:hidden">
            <span className="h-2 w-2 animate-pulse rounded-full bg-neon" /> NETTRIAGE
          </a>
          <div className="min-w-0 flex-1 basis-56">
            <h1 className="text-[22px] font-semibold text-white">Dashboard</h1>
            <p className="text-[13px] text-muted">Is your network broken, or breached?</p>
          </div>
          <label className="flex min-w-0 flex-1 basis-60 items-center gap-2 rounded-[10px] border border-line bg-surface px-3 py-2 text-muted transition-shadow focus-within:border-neon/60 focus-within:shadow-[0_0_0_3px_rgb(var(--neon)/0.15)] sm:max-w-xs">
            <span className="sr-only">Search analyses and samples</span>
            <input ref={search} type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search analyses and samples"
              className="min-w-0 flex-1 bg-transparent text-[13px] text-ink outline-none placeholder:text-muted" />
            <kbd className="kbd text-[11px]">/</kbd>
          </label>
          <button type="button" onClick={() => setModal("upload")} aria-keyshortcuts="U"
            className="nt-btn nt-primary inline-flex items-center gap-2 rounded-[10px] bg-neon px-4 py-2.5 font-mono text-[13px] font-bold text-on-primary shadow-glow">
            <Plus size={15} /> New analysis
          </button>
        </header>

        <main className="mx-auto flex max-w-[1120px] flex-col gap-7 px-4 pb-16 pt-7 sm:px-8">
          <button type="button" onClick={() => setModal("upload")} {...dropProps} disabled={busy}
            className={`nt-drop ${over ? "is-over" : ""} flex flex-wrap items-center gap-6 rounded-2xl bg-surface px-6 py-7 text-left sm:px-8`}>
            <span className="w-24 shrink-0 sm:w-28"><RadarDish className="w-full" active={over} /></span>
            <span className="flex min-w-0 flex-1 basis-72 flex-col gap-1.5">
              <span className="font-mono text-[20px] font-bold text-white">{busy ? "Starting the analysis..." : over ? "Release to analyse" : "Drop a capture to analyse"}</span>
              <span className="text-muted">.pcap, .pcapng or .cap, up to {limit}. Checked first, analysed in isolation, deleted after.</span>
            </span>
            <span className="nt-btn nt-primary inline-flex items-center gap-2 rounded-[10px] bg-neon px-4 py-2.5 font-mono text-[13px] font-bold text-on-primary">
              <Upload size={15} /> Choose file
            </span>
          </button>

          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Stat label="Analyses this session" value={recent.length} />
            <Stat label="Attacks found" value={totals.attacks} dot="bg-attack" tone="text-attack" />
            <Stat label="Faults found" value={totals.faults} dot="bg-fault" tone="text-fault" />
            <Stat label="Clean captures" value={totals.clean} dot="bg-benign" tone="text-benign" />
          </div>

          <section id="recent" className="scroll-mt-6 overflow-hidden rounded-2xl border border-line bg-surface shadow-card">
            <header className="flex items-center justify-between border-b border-line px-5 py-4">
              <h2 className="text-[15px] font-semibold text-white">Recent analyses</h2>
              <span className="text-[12.5px] text-muted">Kept for {config?.retention_minutes ?? 60} minutes</span>
            </header>
            {shownRecent.length === 0 ? (
              <p className="px-5 py-10 text-center text-muted">
                {recent.length ? "No analyses match your search." : "No analyses yet. Drop a capture above, or run one from the library."}
              </p>
            ) : (
              <div className="overflow-x-auto">
                <div className="min-w-[720px]">
                  <div className="grid grid-cols-[minmax(0,2.2fr)_minmax(0,1.3fr)_100px_110px_190px] gap-3 px-5 py-2.5 font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-muted">
                    <span>Capture</span><span>Result</span><span>Packets</span><span>Analysed</span><span className="text-right">Actions</span>
                  </div>
                  {shownRecent.map((r) => <RecentRow key={r.id} r={r} onDelete={() => remove(r.id)} />)}
                </div>
              </div>
            )}
          </section>

          <section id="library" className="flex scroll-mt-6 flex-col gap-4">
            <div className="flex flex-wrap items-end justify-between gap-3">
              <div>
                <h2 className="text-[15px] font-semibold text-white">Library</h2>
                <p className="text-[13px] text-muted">Labelled sample captures. Run any of them in one click.</p>
              </div>
              <div className="flex flex-wrap gap-1.5 text-[12.5px]" role="group" aria-label="Filter the library">
                {FILTERS.map((fl) => {
                  const n = fl.key === "all" ? samples.length : samples.filter((s) => s.category === fl.key).length;
                  if (!n) return null;
                  const on = filter === fl.key;
                  return (
                    <button key={fl.key} type="button" aria-pressed={on} onClick={() => setFilter(fl.key)}
                      className={`rounded-full border px-3 py-1 transition-colors ${on ? "border-neon/50 bg-neon/10 text-neon" : "border-line text-muted hover:border-neon/45 hover:text-ink"}`}>
                      {fl.label} {n}
                    </button>
                  );
                })}
              </div>
            </div>
            {library.length === 0 ? (
              <p className="rounded-2xl border border-line bg-surface px-5 py-10 text-center text-muted">No samples match your search.</p>
            ) : (
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {library.map((s) => (
                  <button key={s.name} type="button" disabled={busy} onClick={() => runSample(s.name)} title={s.description}
                    className="nt-lift group relative flex flex-col gap-3.5 overflow-hidden rounded-[14px] border border-line bg-surface p-[18px] text-left shadow-card disabled:cursor-wait">
                    <span className="flex items-center justify-between gap-2">
                      <CategoryChip category={s.category} />
                      <span className="font-mono text-[11.5px] text-muted">{bytes(s.size)}</span>
                    </span>
                    <span className="text-[14.5px] font-semibold leading-snug text-white">{s.title}</span>
                    <span className="mt-auto flex items-center justify-between gap-2">
                      <span className="truncate font-mono text-[11.5px] text-muted">{s.name}</span>
                      <span className="nt-reveal shrink-0 font-mono text-[12px] font-bold tracking-[0.1em] text-neon">RUN <span className="nt-arrow">▸</span></span>
                    </span>
                  </button>
                ))}
              </div>
            )}
          </section>
        </main>
      </div>

      {checking && <VerifyPackDialog onClose={() => setChecking(false)} />}
      {modal && (
        <UploadModal tab={modal} setTab={setModal} onClose={closeModal} samples={samples} busy={busy} limit={limit}
          error={error} onUpload={upload} onSample={runSample} />
      )}
      {error && !modal && (
        <div role="alert" className={`fixed inset-x-0 bottom-6 z-40 mx-auto flex w-[min(620px,calc(100%-2rem))] items-start gap-3 rounded-xl border bg-surface p-4 font-mono shadow-lift ${error.refused ? "border-neon/50" : "border-attack/60"}`}>
          <ShieldAlert size={18} className={`mt-0.5 shrink-0 ${error.refused ? "text-neon" : "text-attack"}`} />
          <div className="min-w-0 flex-1">
            <p className={`text-[13px] font-bold uppercase tracking-[0.12em] ${error.refused ? "text-neon" : "text-attack"}`}>{error.refused ? "File refused" : "Could not start"}</p>
            <p className="mt-1 text-[13px]">{error.text}</p>
          </div>
          <button type="button" className="btn px-2" onClick={() => setError(null)} aria-label="Dismiss"><X size={14} /></button>
        </div>
      )}
    </div>
  );
}

function NavButton({ target, icon, label, count }: { target: string; icon: ReactNode; label: string; count: number }) {
  return (
    <button type="button" onClick={() => document.getElementById(target)?.scrollIntoView({ behavior: "smooth" })}
      className="nt-nav flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-muted">
      {icon} {label}<span className="ml-auto font-mono text-[11px]">{count}</span>
    </button>
  );
}

function Stat({ label, value, dot, tone = "text-white" }: { label: string; value: number; dot?: string; tone?: string }) {
  return (
    <div className="nt-lift rounded-[14px] border border-line bg-surface p-[18px] shadow-card">
      <p className="flex items-center gap-1.5 text-[12.5px] text-muted">{dot && <span className={`h-2 w-2 rounded-full ${dot}`} />}{label}</p>
      <p className={`mt-1.5 font-mono text-[28px] font-bold ${value && dot ? `glow-text ${tone}` : "text-white"}`}>{value}</p>
    </div>
  );
}

export function CategoryChip({ category, wide = false }: { category: string; wide?: boolean }) {
  const c = CATEGORIES[category] ?? { label: category, chip: "bg-ink/[0.08] text-ink" };
  return (
    <span className={`rounded-full px-2 py-0.5 text-center font-mono text-[10.5px] font-semibold uppercase tracking-[0.12em] ${c.chip} ${wide ? "w-[88px] shrink-0" : ""}`}>
      {c.label}
    </span>
  );
}

function RecentRow({ r, onDelete }: { r: Recent; onDelete: () => void }) {
  const verdict = r.attacks ? "attack" : r.faults ? "fault" : "benign";
  const text = r.attacks ? `${r.attacks} attack${r.attacks > 1 ? "s" : ""}` : r.faults ? `${r.faults} fault${r.faults > 1 ? "s" : ""}` : "Clean";
  const tone = { attack: "text-attack", fault: "text-fault", benign: "text-benign" }[verdict];
  return (
    <div className="nt-row grid grid-cols-[minmax(0,2.2fr)_minmax(0,1.3fr)_100px_110px_190px] items-center gap-3 border-t border-line px-5 py-3.5">
      <a href={href(`/a/${r.id}`)} className="min-w-0">
        <span className="block truncate font-semibold text-white hover:text-neon">{r.name}</span>
        <span className="font-mono text-[11.5px] text-muted">{r.size != null ? bytes(r.size) : " "}</span>
      </a>
      <span className="flex items-center gap-1.5">
        {verdict === "benign" ? (
          <span className="inline-flex items-center gap-1 rounded-md border border-benign/35 bg-benign/10 px-1.5 py-0.5 text-[11px] font-semibold text-benign">
            <CheckCircle size={12} /> Clean
          </span>
        ) : (
          <><VerdictChip verdict={verdict} size="sm" /><span className={`text-[12.5px] ${tone}`}>{text}</span></>
        )}
      </span>
      <span className="font-mono text-[12.5px]">{r.packets != null ? num(r.packets) : "-"}</span>
      <span className="text-[12.5px] text-muted">{ago(r.at)}</span>
      <span className="flex items-center justify-end gap-1.5">
        <a href={href(`/a/${r.id}`)} className="nt-reveal font-mono text-[12.5px] font-semibold text-neon">Open <span className="nt-arrow">›</span></a>
        <a href={api.reportUrl(r.id)} download title="Export the report (JSON)" aria-label={`Export the report for ${r.name}`}
          className="flex rounded-lg border border-line p-[7px] text-muted transition-colors hover:border-neon/50 hover:text-neon"><Download size={15} /></a>
        <button type="button" onClick={onDelete} title="Delete now" aria-label={`Delete the report for ${r.name}`}
          className="flex rounded-lg border border-line p-[7px] text-muted transition-colors hover:border-attack/50 hover:text-attack"><Trash size={15} /></button>
      </span>
    </div>
  );
}

function UploadModal({ tab, setTab, onClose, samples, busy, limit, error, onUpload, onSample }: {
  tab: Tab; setTab: (t: Tab) => void; onClose: () => void; samples: Sample[]; busy: boolean; limit: string;
  error: Problem | null; onUpload: (f: File) => void; onSample: (name: string) => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [picked, setPicked] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [over, setOver] = useState(false);
  const closeRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const before = document.activeElement as HTMLElement | null;
    closeRef.current?.focus();
    return () => before?.focus();
  }, []);

  // Keep Tab inside the dialog while it is open.
  const trapTab = (e: ReactKeyboardEvent<HTMLDivElement>) => {
    if (e.key !== "Tab") return;
    const items = [...e.currentTarget.querySelectorAll<HTMLElement>("button:not(:disabled), input, a[href], [tabindex]:not([tabindex='-1'])")]
      .filter((el) => el.offsetParent !== null || el.getClientRects().length > 0);
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  };

  const q = query.trim().toLowerCase();
  const list = samples.filter((s) => !q || s.title.toLowerCase().includes(q) || s.name.toLowerCase().includes(q));
  const ready = tab === "upload" ? !!file : !!picked;
  const go = () => {
    if (tab === "upload" && file) onUpload(file);
    if (tab === "library" && picked) onSample(picked);
  };
  const tabClass = (t: Tab) => `flex flex-1 items-center justify-center gap-2 rounded-[7px] py-2 transition-colors ${tab === t
    ? "bg-surface text-neon shadow-[0_1px_0_rgb(0_0_0/0.5),inset_0_0_0_1px_rgb(var(--neon)/0.35)]" : "text-muted hover:text-ink"}`;

  return (
    <div className="nt-backdrop fixed inset-0 z-50 flex items-center justify-center bg-bg/70 p-4 backdrop-blur-sm sm:p-6"
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div role="dialog" aria-modal="true" aria-labelledby="upload-title" onKeyDown={trapTab}
        className="nt-modal w-full max-w-[640px] overflow-hidden rounded-[18px] border border-neon/30 bg-surface shadow-[0_40px_80px_-30px_rgb(0_0_0/0.95),0_0_60px_-20px_rgb(var(--neon)/0.35)]">
        <header className="flex items-center justify-between gap-3 border-b border-line px-5 py-4">
          <h2 id="upload-title" className="text-[17px] font-semibold text-white">New analysis</h2>
          <button ref={closeRef} type="button" onClick={onClose} aria-label="Close"
            className="flex rounded-lg border border-line p-2 text-muted transition-colors hover:border-neon/50 hover:text-neon"><X size={15} /></button>
        </header>
        <div role="tablist" className="mx-5 mt-4 flex gap-1 rounded-[10px] border border-line bg-bg p-1 text-[13px] font-semibold">
          <button type="button" role="tab" aria-selected={tab === "upload"} onClick={() => setTab("upload")} className={tabClass("upload")}><Upload size={14} /> Upload</button>
          <button type="button" role="tab" aria-selected={tab === "library"} onClick={() => setTab("library")} className={tabClass("library")}><FileIcon size={14} /> From library</button>
        </div>

        {tab === "upload" ? (
          <div className="px-5 pb-5 pt-4">
            <label onDragOver={(e) => { e.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)}
              onDrop={(e) => { e.preventDefault(); setOver(false); const f = e.dataTransfer.files?.[0]; if (f) setFile(f); }}
              className={`nt-drop ${over ? "is-over" : ""} flex cursor-pointer flex-col items-center gap-3 rounded-[14px] bg-bg px-6 py-9 text-center`}>
              <span className="flex h-14 w-14 items-center justify-center rounded-2xl bg-neon/10 text-neon shadow-glow"><Upload size={24} /></span>
              {file ? (
                <>
                  <span className="max-w-full truncate font-mono text-[16px] font-bold text-white">{file.name}</span>
                  <span className="text-[13px] text-muted">{bytes(file.size)} · <span className="text-neon underline underline-offset-[3px]">choose another</span></span>
                </>
              ) : (
                <>
                  <span className="font-mono text-[16px] font-bold text-white">Drop your capture here</span>
                  <span className="text-[13px] text-muted">or <span className="text-neon underline underline-offset-[3px]">choose a file</span> · .pcap, .pcapng, .cap · up to {limit}</span>
                </>
              )}
              <input type="file" accept=".pcap,.pcapng,.cap" className="sr-only" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
            </label>
          </div>
        ) : (
          <div className="flex flex-col gap-3 px-5 pb-5 pt-4">
            <label className="flex items-center gap-2 rounded-[10px] border border-line bg-bg px-3 py-2 transition-shadow focus-within:border-neon/60 focus-within:shadow-[0_0_0_3px_rgb(var(--neon)/0.15)]">
              <span className="sr-only">Search the library</span>
              <input type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder={`Search ${samples.length} sample captures`}
                className="min-w-0 flex-1 bg-transparent text-[13px] text-ink outline-none placeholder:text-muted" />
            </label>
            <div className="max-h-[300px] overflow-y-auto rounded-xl border border-line" role="listbox" aria-label="Sample captures">
              {list.length === 0 && <p className="px-4 py-6 text-center text-muted">No samples match.</p>}
              {list.map((s) => {
                const on = picked === s.name;
                return (
                  <button key={s.name} type="button" role="option" aria-selected={on} onClick={() => setPicked(s.name)} onDoubleClick={() => onSample(s.name)}
                    className={`nt-row flex w-full items-center gap-3 border-b border-line px-3.5 py-3 text-left last:border-b-0 ${on ? "bg-neon/[0.08] shadow-[inset_3px_0_0_rgb(var(--neon))]" : ""}`}>
                    <CategoryChip category={s.category} wide />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-[13.5px] font-semibold text-white">{s.title}</span>
                      <span className="font-mono text-[11px] text-muted">{s.name} · {bytes(s.size)}</span>
                    </span>
                    <span className={`${on ? "" : "nt-reveal"} shrink-0 font-mono text-[12px] font-bold text-neon`}>{on ? "SELECTED" : "PICK"}</span>
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {error && (
          <p role="alert" className={`mx-5 mb-4 rounded-lg border px-3 py-2 text-[13px] ${error.refused ? "border-neon/40 text-neon" : "border-attack/50 text-attack"}`}>
            <span className="font-semibold">{error.refused ? "File refused: " : "Could not start: "}</span>{error.text}
          </p>
        )}

        <footer className="flex flex-wrap items-center justify-end gap-2 border-t border-line bg-bg px-5 py-3.5">
          <button type="button" onClick={onClose} className="nt-btn nt-ghost rounded-[10px] border border-line bg-surface px-4 py-2.5 font-mono text-[13px] font-semibold">Cancel</button>
          <button type="button" onClick={go} disabled={!ready || busy}
            className="nt-btn nt-primary inline-flex items-center gap-2 rounded-[10px] bg-neon px-4 py-2.5 font-mono text-[13px] font-bold text-on-primary shadow-glow disabled:cursor-not-allowed disabled:opacity-40 disabled:shadow-none">
            {busy ? "Starting..." : <>Analyse <span className="nt-arrow">→</span></>}
          </button>
        </footer>
      </div>
    </div>
  );
}
