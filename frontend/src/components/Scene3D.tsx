// Decorative 3D scenes built from plain CSS transforms: no WebGL, no libraries, nothing loaded
// from the network. They respect prefers-reduced-motion (see index.css).
import type { CSSProperties } from "react";

export type Faces = { top: string; light: string; dark: string };

const NAVY: Faces = { top: "#2c4573", light: "#22375e", dark: "#162641" };
const GOLD: Faces = { top: "#e2c058", light: "#c9a227", dark: "#9c7c15" };
const RED: Faces = { top: "#d9534f", light: "#b52f2b", dark: "#86201d" };
const PALE: Faces = { top: "#f8f7f4", light: "#dcd7ca", dark: "#b9b2a1" };

export function Box({ x, y, w, d, h, c, children }: {
  x: number; y: number; w: number; d: number; h: number; c: Faces; children?: React.ReactNode;
}) {
  const face = (style: CSSProperties, bg: string) => <div className="face" style={{ ...style, background: bg }} />;
  return (
    <div className="preserve-3d absolute" style={{ left: x, top: y, width: w, height: d }}>
      {face({ left: 0, top: 0, width: w, height: h, transformOrigin: "top", transform: "rotateX(90deg)" }, c.dark)}
      {face({ left: 0, top: 0, width: h, height: d, transformOrigin: "left", transform: "rotateY(-90deg)" }, c.dark)}
      {face({ left: 0, top: d - h, width: w, height: h, transformOrigin: "bottom", transform: "rotateX(-90deg)" }, c.light)}
      {face({ left: w - h, top: 0, width: h, height: d, transformOrigin: "right", transform: "rotateY(90deg)" }, c.light)}
      {face({ left: 0, top: 0, width: w, height: d, transform: `translateZ(${h}px)` }, c.top)}
      {children}
    </div>
  );
}

// A label that always faces the viewer, floating above a node.
function Tag({ text, z, tone = "light" }: { text: string; z: number; tone?: "light" | "alert" | "gold" }) {
  const cls = { light: "bg-white/95 text-navy", alert: "bg-attack text-white", gold: "bg-gold text-navy" }[tone];
  return (
    <div className="preserve-3d absolute left-1/2 top-1/2"
      style={{ transform: `translate(-50%, -50%) translateZ(${z}px) rotateZ(38deg) rotateX(-58deg)` }}>
      <span className={`block whitespace-nowrap rounded-md px-2 py-0.5 text-[11px] font-semibold shadow-lg ${cls}`}>{text}</span>
    </div>
  );
}

type Node = { id: string; x: number; y: number; w: number; h: number; c: Faces };
const NODES: Node[] = [
  { id: "router", x: 190, y: 190, w: 76, h: 44, c: GOLD },
  { id: "server", x: 330, y: 50, w: 56, h: 92, c: NAVY },
  { id: "pc1", x: 50, y: 70, w: 46, h: 26, c: PALE },
  { id: "pc2", x: 40, y: 300, w: 46, h: 26, c: PALE },
  { id: "pc3", x: 200, y: 370, w: 46, h: 26, c: PALE },
  { id: "intruder", x: 360, y: 300, w: 44, h: 30, c: RED },
];
const center = (id: string) => {
  const n = NODES.find((m) => m.id === id)!;
  return { x: n.x + n.w / 2, y: n.y + n.w / 2 };
};
const LINKS = ["server", "pc1", "pc2", "pc3", "intruder"].map((id) => ["router", id]);
const PACKETS: { from: string; to: string; dur: number; delay: number; red?: boolean }[] = [
  { from: "pc1", to: "router", dur: 2.2, delay: 0 },
  { from: "router", to: "server", dur: 2.6, delay: 0.6 },
  { from: "pc2", to: "router", dur: 2.4, delay: 1.1 },
  { from: "server", to: "router", dur: 2.8, delay: 1.7 },
  { from: "router", to: "pc3", dur: 2.3, delay: 0.3 },
  { from: "intruder", to: "router", dur: 1.6, delay: 0.2, red: true },
  { from: "intruder", to: "pc3", dur: 1.9, delay: 1.0, red: true },
];

export function NetworkDiorama() {
  return (
    <div className="relative mx-auto h-[400px] w-full max-w-[520px] select-none [perspective:1300px]" aria-hidden="true">
      <div className="preserve-3d absolute left-1/2 top-1/2 h-[440px] w-[440px] -translate-x-1/2 -translate-y-1/2">
        <div className="preserve-3d absolute inset-0 animate-sway" style={{ transform: "rotateX(58deg) rotateZ(-38deg)" }}>
          <div className="grid-floor absolute inset-0 rounded-[28px] shadow-[0_40px_80px_-20px_rgba(0,0,0,0.6)]" />
          <svg className="absolute inset-0" width="440" height="440" viewBox="0 0 440 440">
            {LINKS.map(([a, b]) => {
              const p = center(a);
              const q = center(b);
              return <line key={b} x1={p.x} y1={p.y} x2={q.x} y2={q.y} stroke={b === "intruder" ? "#d9534f" : "#c9a227"}
                strokeWidth="2" strokeDasharray="6 6" opacity="0.8" />;
            })}
          </svg>
          {/* Warning ripple under the intruder */}
          <div className="absolute h-[90px] w-[90px] animate-pulse3d rounded-full border-2 border-[#d9534f]"
            style={{ left: center("intruder").x - 45, top: center("intruder").y - 45 }} />
          {NODES.map((n) => (
            <Box key={n.id} x={n.x} y={n.y} w={n.w} d={n.w} h={n.h} c={n.c}>
              {n.id === "router" && <Tag text="Router" z={n.h + 34} tone="gold" />}
              {n.id === "server" && <Tag text="File server" z={n.h + 30} />}
              {n.id === "intruder" && <Tag text="Who is this?" z={n.h + 34} tone="alert" />}
            </Box>
          ))}
          {PACKETS.map((p, i) => {
            const a = center(p.from);
            const b = center(p.to);
            return (
              <div key={i} className="preserve-3d absolute left-0 top-0 animate-hop"
                style={{
                  ["--x1" as string]: `${a.x - 6}px`, ["--y1" as string]: `${a.y - 6}px`,
                  ["--x2" as string]: `${b.x - 6}px`, ["--y2" as string]: `${b.y - 6}px`,
                  ["--dur" as string]: `${p.dur}s`, animationDelay: `${p.delay}s`,
                } as CSSProperties}>
                <Box x={0} y={0} w={12} d={12} h={12} c={p.red ? RED : GOLD} />
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

const LAYERS = [
  { name: "Ethernet & ARP", note: "who owns which address" },
  { name: "IP", note: "where packets go, and their TTL" },
  { name: "TCP & UDP", note: "loss, resets, slow handshakes" },
  { name: "DNS & DHCP", note: "names and network settings" },
];

// The protocol layers NetTriage reads, stacked in 3D. Attacks show up as contradictions between them.
export function LayerStack() {
  return (
    <div className="relative mx-auto h-[330px] w-full max-w-[420px] select-none [perspective:1000px]" aria-hidden="true">
      <div className="preserve-3d absolute left-1/2 top-[58%] h-[210px] w-[210px] -translate-x-1/2 -translate-y-1/2 animate-spinY"
        style={{ transform: "rotateX(62deg)" }}>
        {LAYERS.map((l, i) => (
          <div key={l.name}
            className={`absolute inset-0 flex flex-col items-center justify-center rounded-2xl border text-center ${i === 3
              ? "border-gold bg-gold/25" : "border-white/25 bg-[#1f3157]/80"}`}
            style={{ transform: `translateZ(${i * 42}px)`, boxShadow: "0 18px 40px -12px rgba(0,0,0,0.45)" }}>
            <span className={`text-[15px] font-semibold ${i === 3 ? "text-[#f3dd8f]" : "text-white"}`}>{l.name}</span>
            <span className="mt-1 text-[11px] text-white/70">{l.note}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// A small 3D seal used as the report's verdict emblem.
export function VerdictSeal({ tone }: { tone: "attack" | "fault" | "ok" }) {
  const c = tone === "attack" ? RED : tone === "fault" ? GOLD : { top: "#3aa77a", light: "#26764f", dark: "#1a5639" };
  return (
    <div className="relative h-16 w-16 shrink-0 [perspective:400px]" aria-hidden="true">
      <div className="preserve-3d absolute inset-0 animate-float" style={{ transform: "rotateX(52deg) rotateZ(-30deg)" }}>
        <Box x={8} y={8} w={48} d={48} h={14} c={c} />
      </div>
    </div>
  );
}
