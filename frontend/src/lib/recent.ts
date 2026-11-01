// Recently opened reports, kept only in this browser tab's session. The server forgets reports
// after its retention time, so entries older than that are dropped too.
export interface Recent {
  id: string;
  name: string;
  at: number;
  attacks: number;
  faults: number;
  packets?: number;
  size?: number;
}

const KEY = "nettriage.recent";
const MAX_AGE_MS = 60 * 60 * 1000;

export function listRecent(): Recent[] {
  try {
    const raw = window.sessionStorage.getItem(KEY);
    const items = raw ? (JSON.parse(raw) as Recent[]) : [];
    return items.filter((r) => typeof r.id === "string" && Date.now() - r.at < MAX_AGE_MS).slice(0, 6);
  } catch {
    return [];
  }
}

export function addRecent(entry: Recent) {
  try {
    const rest = listRecent().filter((r) => r.id !== entry.id);
    window.sessionStorage.setItem(KEY, JSON.stringify([entry, ...rest].slice(0, 6)));
  } catch {
    /* storage unavailable: the list just stays empty */
  }
}

export function forgetRecent(id: string) {
  try {
    window.sessionStorage.setItem(KEY, JSON.stringify(listRecent().filter((r) => r.id !== id)));
  } catch {
    /* ignore */
  }
}
