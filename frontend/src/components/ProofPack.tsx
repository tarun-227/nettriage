// Proof Packs: build one for a report (addresses pseudonymized, contents removed, changes detectable),
// and check one someone sent you. The server does the work; these dialogs show the root hash and the verdict.
import { useEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { api, ApiError } from "../lib/api";
import { bytes } from "../lib/format";
import type { PackCheck, ProofPackInfo } from "../lib/types";
import { Check, Download, Fingerprint, Lock, ShieldAlert, Trash, Upload, X } from "./icons";
import { CopyButton } from "./ui";

function Dialog({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  const close = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    close.current?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  // A portal, because a parent with backdrop-filter (the sticky header) would trap a fixed overlay inside itself.
  return createPortal(
    <div className="nt-backdrop fixed inset-0 z-50 flex items-center justify-center bg-bg/70 p-4 backdrop-blur-sm sm:p-6"
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div role="dialog" aria-modal="true" aria-labelledby="pack-title"
        className="nt-modal w-full max-w-[560px] overflow-hidden rounded-[18px] border border-neon/30 bg-surface shadow-[0_40px_80px_-30px_rgb(0_0_0/0.95),0_0_60px_-20px_rgb(var(--neon)/0.35)]">
        <header className="flex items-center justify-between gap-3 border-b border-line px-5 py-4">
          <h2 id="pack-title" className="flex items-center gap-2.5 text-[17px] font-semibold text-white"><span className="text-neon"><Fingerprint size={17} /></span>{title}</h2>
          <button ref={close} type="button" onClick={onClose} aria-label="Close"
            className="flex rounded-lg border border-line p-2 text-muted transition-colors hover:border-neon/50 hover:text-neon"><X size={15} /></button>
        </header>
        <div className="flex flex-col gap-4 px-5 py-5">{children}</div>
      </div>
    </div>,
    document.body,
  );
}

const PROMISES = [
  { Icon: Lock, text: "Addresses replaced" },
  { Icon: Trash, text: "Packet contents removed" },
  { Icon: Fingerprint, text: "Any change is detectable" },
];

export function ProofPackDialog({ jobId, onClose }: { jobId: string; onClose: () => void }) {
  const [pack, setPack] = useState<ProofPackInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api.proofPack(jobId).then(setPack).catch((e) => setError(e instanceof ApiError ? e.message : "Could not build the Proof Pack."));
  }, [jobId]);

  return (
    <Dialog title="Proof Pack" onClose={onClose}>
      <p className="text-[14px] leading-relaxed text-muted">Evidence you can share without sharing your network.</p>
      <div className="grid gap-2 sm:grid-cols-3">
        {PROMISES.map(({ Icon, text }) => (
          <span key={text} className="flex items-center gap-2 rounded-[10px] border border-line px-3 py-2.5 text-[12.5px]">
            <span className="text-neon"><Icon size={15} /></span>{text}
          </span>
        ))}
      </div>
      {error && <p role="alert" className="rounded-[10px] border border-attack/50 bg-attack/10 px-3 py-2.5 text-[13px] text-attack">{error}</p>}
      {!pack && !error && (
        <p className="flex items-center gap-2.5 font-mono text-[13px] text-muted"><span className="h-2 w-2 animate-pulse rounded-full bg-neon" /> Packing and hashing...</p>
      )}
      {pack && (
        <>
          <div className="rounded-[12px] border border-neon/35 bg-bg p-3.5">
            <div className="mb-2 flex items-center justify-between gap-2">
              <span className="font-mono text-[11px] font-semibold uppercase tracking-[0.16em] text-neon">Root hash</span>
              <CopyButton text={pack.root} label="Copy" />
            </div>
            <code className="block break-all font-mono text-[13px] leading-relaxed text-white">{pack.root}</code>
            <p className="mt-2 text-[12px] text-muted">Send this separately from the file. If they match, nothing was changed.</p>
          </div>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <span className="font-mono text-[12px] text-muted">{pack.files.length} files · {bytes(pack.bytes)}</span>
            <a href={api.proofPackUrl(jobId, pack.token)} download
              className="nt-btn nt-primary inline-flex items-center gap-2 rounded-[10px] bg-neon px-4 py-2.5 font-mono text-[13px] font-bold text-on-primary shadow-glow">
              <Download size={15} /> Download Proof Pack
            </a>
          </div>
        </>
      )}
    </Dialog>
  );
}

export function VerifyPackDialog({ onClose }: { onClose: () => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [root, setRoot] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<PackCheck | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [over, setOver] = useState(false);
  const rootOk = root === "" || /^[0-9a-fA-F]{64}$/.test(root.trim());

  async function check() {
    if (!file || !rootOk) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.verifyPack(file, root.trim() || undefined));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not check the file.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog title="Check a Proof Pack" onClose={onClose}>
      <label onDragOver={(e) => { e.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)}
        onDrop={(e) => { e.preventDefault(); setOver(false); const f = e.dataTransfer.files?.[0]; if (f) { setFile(f); setResult(null); } }}
        className={`nt-drop ${over ? "is-over" : ""} flex cursor-pointer flex-col items-center gap-2.5 rounded-[14px] bg-bg px-6 py-7 text-center`}>
        <span className="flex h-12 w-12 items-center justify-center rounded-2xl bg-neon/10 text-neon"><Upload size={22} /></span>
        <span className="max-w-full truncate font-mono text-[14px] font-bold text-white">{file ? file.name : "Drop a Proof Pack (.zip)"}</span>
        <span className="text-[12.5px] text-muted">{file ? bytes(file.size) : "or click to choose one"}</span>
        <input type="file" accept=".zip,application/zip" className="sr-only"
          onChange={(e) => { const f = e.target.files?.[0]; if (f) { setFile(f); setResult(null); } }} />
      </label>
      <label className="flex flex-col gap-1.5 text-[12.5px] text-muted">
        Root hash you were given (optional)
        <input value={root} onChange={(e) => setRoot(e.target.value)} spellCheck={false} placeholder="64 hexadecimal characters"
          className={`rounded-[10px] border bg-bg px-3 py-2.5 font-mono text-[12.5px] text-ink outline-none transition-colors focus:border-neon/60 ${rootOk ? "border-line" : "border-attack/60"}`} />
      </label>
      {error && <p role="alert" className="rounded-[10px] border border-attack/50 bg-attack/10 px-3 py-2.5 text-[13px] text-attack">{error}</p>}
      {result && (
        <div role="status" className={`nt-open rounded-[12px] border p-4 ${result.ok ? "border-benign/50 bg-benign/[0.07]" : "border-attack/50 bg-attack/[0.07]"}`}>
          <p className={`flex items-center gap-2 font-mono text-[15px] font-bold ${result.ok ? "text-benign" : "text-attack"}`}>
            {result.ok ? <Check size={17} /> : <ShieldAlert size={17} />} {result.ok ? "VERIFIED" : "NOT VERIFIED"}
          </p>
          {result.root && <p className="mt-1.5 break-all font-mono text-[11.5px] text-muted">root {result.root}</p>}
          {result.ok && !root && <p className="mt-1.5 text-[12.5px] text-muted">Every file matches its manifest. Compare the root with the one you were given.</p>}
          {result.problems.length > 0 && (
            <ul className="mt-2 flex flex-col gap-1 text-[13px]">{result.problems.map((p) => <li key={p}>▸ {p}</li>)}</ul>
          )}
        </div>
      )}
      <div className="flex justify-end gap-2">
        <button type="button" onClick={onClose} className="nt-btn nt-ghost rounded-[10px] border border-line bg-surface px-4 py-2.5 font-mono text-[13px] font-semibold">Close</button>
        <button type="button" onClick={check} disabled={!file || !rootOk || busy}
          className="nt-btn nt-primary inline-flex items-center gap-2 rounded-[10px] bg-neon px-4 py-2.5 font-mono text-[13px] font-bold text-on-primary shadow-glow disabled:cursor-not-allowed disabled:opacity-50">
          {busy ? "Checking..." : "Check"}
        </button>
      </div>
    </Dialog>
  );
}
