// A 3D box built from plain CSS transforms: no WebGL, no libraries, nothing loaded from the network.
import type { CSSProperties } from "react";

export type Faces = { top: string; light: string; dark: string };

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
