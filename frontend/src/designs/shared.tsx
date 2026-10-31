// Shared plumbing for the design concepts: every concept really uploads and analyses captures.
import { useEffect, useRef, useState, type DragEvent } from "react";
import { api, ApiError } from "../lib/api";
import { href, navigate } from "../lib/router";
import type { Sample } from "../lib/types";

export const FEATURED = ["arp_spoof_mitm.pcap", "dns_spoof_race.pcap", "uplink_outage.pcap", "port_scan_syn.pcap",
  "xss_payloads.pcap"];

export function useAnalyse() {
  const [samples, setSamples] = useState<Sample[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [over, setOver] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    api.samples().then(setSamples).catch(() => setSamples([]));
  }, []);

  async function run(fn: () => Promise<{ id: string }>) {
    setBusy(true);
    setError(null);
    try {
      const { id } = await fn();
      navigate(`/a/${id}`);
      window.scrollTo({ top: 0 });
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Something went wrong.");
      setBusy(false);
    }
  }

  const onFile = (f?: File) => f && run(() => api.upload(f));
  const featured = FEATURED.map((n) => samples.find((s) => s.name === n)).filter(Boolean) as Sample[];

  return {
    samples, featured, busy, error, over,
    clearError: () => setError(null),
    pickFile: () => input.current?.click(),
    sample: (name: string) => run(() => api.analyseSample(name)),
    randomSample: () => featured.length && run(() => api.analyseSample(featured[Math.floor(Math.random() * featured.length)].name)),
    fileInput: (
      <input ref={input} type="file" accept=".pcap,.pcapng,.cap" className="hidden" onChange={(e) => onFile(e.target.files?.[0])} />
    ),
    dropProps: {
      onDragOver: (e: DragEvent) => { e.preventDefault(); setOver(true); },
      onDragLeave: () => setOver(false),
      onDrop: (e: DragEvent) => { e.preventDefault(); setOver(false); onFile(e.dataTransfer.files?.[0]); },
    },
  };
}

// Animates from 0 to `target` once, for live-feeling numbers.
export function useCountUp(target: number, ms = 1400) {
  const [v, setV] = useState(0);
  useEffect(() => {
    let raf = 0;
    const t0 = performance.now();
    const tick = (t: number) => {
      const p = Math.min(1, (t - t0) / ms);
      setV(Math.round(target * (1 - Math.pow(1 - p, 3))));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, ms]);
  return v;
}

export function useNow(every = 1000) {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), every);
    return () => clearInterval(id);
  }, [every]);
  return now;
}

export function useCycle(length: number, every = 1800) {
  const [i, setI] = useState(0);
  useEffect(() => {
    if (!length) return;
    const id = setInterval(() => setI((x) => (x + 1) % length), every);
    return () => clearInterval(id);
  }, [length, every]);
  return i;
}

export function ErrorToast({ text, onClose, className }: { text: string | null; onClose: () => void; className: string }) {
  if (!text) return null;
  return (
    <div role="alert" className={`fixed inset-x-0 bottom-6 z-50 mx-auto flex w-[min(520px,calc(100%-2rem))] items-center gap-3 px-4 py-3 ${className}`}>
      <span className="flex-1 text-[14px]">{text}</span>
      <button type="button" onClick={onClose} className="text-[13px] font-semibold opacity-70 hover:opacity-100">Close</button>
    </div>
  );
}

export function GalleryLink({ className }: { className: string }) {
  return <a href={href("/designs")} className={className}>All designs</a>;
}
