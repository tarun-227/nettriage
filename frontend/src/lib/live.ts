// Small hooks that make the console feel live: a ticking clock, cycling items, typed-out lines.
import { useEffect, useState } from "react";

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

// Types `lines` out one character at a time, pauses, then starts over.
export function useTyped(lines: readonly string[], speed = 22, pause = 420, restart = 2600) {
  const [line, setLine] = useState(0);
  const [chars, setChars] = useState(0);
  useEffect(() => {
    if (line >= lines.length) {
      const id = setTimeout(() => { setLine(0); setChars(0); }, restart);
      return () => clearTimeout(id);
    }
    const full = lines[line].length;
    const id = setTimeout(() => {
      if (chars < full) setChars(chars + 1);
      else { setLine(line + 1); setChars(0); }
    }, chars < full ? speed : pause);
    return () => clearTimeout(id);
  }, [line, chars, lines, speed, pause, restart]);
  return { line, chars };
}

// True while the media query matches, for layouts that change shape rather than just size.
export function useMedia(query: string) {
  const [match, setMatch] = useState(() => window.matchMedia(query).matches);
  useEffect(() => {
    const mq = window.matchMedia(query);
    const on = () => setMatch(mq.matches);
    on();
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, [query]);
  return match;
}
