// Dedupe helpers (pure, unit-tested). An incoming item joins an existing incident from the
// last 72h if any of these match, cheapest first:
//   1. same CVE id                    (news about a KEV entry)
//   2. same normalised victim name    ("Harvard University" ~ "harvard.edu")
//   3. embedding cosine ≥ threshold   (same story, different wording; via Vectorize)

export const DEDUPE_WINDOW_MS = 72 * 3600_000;

export interface Candidate {
  id: number;
  victim_key: string | null;
  cve: string | null;
  first_seen: number;
}

export interface MatchResult {
  id: number;
  reason: 'cve' | 'victim' | 'vector';
  score?: number;
}

export function cosine(a: ArrayLike<number>, b: ArrayLike<number>): number {
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    const x = a[i]!;
    const y = b[i]!;
    dot += x * y;
    na += x * x;
    nb += y * y;
  }
  return na && nb ? dot / Math.sqrt(na * nb) : 0;
}

const LEGAL_SUFFIX =
  /\b(inc|incorporated|llc|ltd|limited|gmbh|ag|sa|sas|srl|spa|s\.?p\.?a|bv|nv|plc|pa|llp|lp|corp|corporation|co|company|group|holdings?|berhad|pty|kg|oy|ab|as)\b\.?/g;
const GENERIC = new Set(['unknown', 'various', 'multiple', 'customers', 'users', 'government', 'city', 'county', 'university', 'hospital', 'school']);

/** Normalise a victim name for matching: lower-case, drop domain TLD, legal suffixes, punctuation. */
export function victimKey(name: string | null | undefined): string | null {
  if (!name) return null;
  let s = name.toLowerCase().trim();
  s = s.replace(/^https?:\/\//, '').replace(/^www\./, '');
  // "marlo-inc.com" / "acme.co.uk" → "marlo-inc" / "acme"
  const domain = s.match(/^([a-z0-9-]+)\.[a-z]{2,}(\.[a-z]{2})?(\/.*)?$/);
  if (domain) s = domain[1]!;
  s = s
    .replace(/[^\p{L}\p{N}]+/gu, ' ')
    .replace(LEGAL_SUFFIX, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (s.length < 4 || GENERIC.has(s)) return null;
  return s;
}

/** Equal, or one is a word-prefix of the other ("harvard" ~ "harvard university"). */
export function victimKeysMatch(a: string | null, b: string | null): boolean {
  if (!a || !b) return false;
  if (a === b) return true;
  const [short, long] = a.length <= b.length ? [a, b] : [b, a];
  return short.length >= 5 && long.startsWith(`${short} `);
}

export function extractCve(text: string): string | null {
  const m = text.match(/\bCVE-\d{4}-\d{4,7}\b/i);
  return m ? m[0].toUpperCase() : null;
}

export function findMatch(
  probe: { victimKey: string | null; cve: string | null },
  candidates: Candidate[],
  vectorHits: { id: number; score: number }[],
  threshold: number,
  now = Date.now(),
): MatchResult | null {
  const recent = candidates.filter((c) => now - c.first_seen <= DEDUPE_WINDOW_MS);
  if (probe.cve) {
    const c = recent.find((x) => x.cve === probe.cve);
    if (c) return { id: c.id, reason: 'cve' };
  }
  if (probe.victimKey) {
    const c = recent.find((x) => victimKeysMatch(x.victim_key, probe.victimKey));
    if (c) return { id: c.id, reason: 'victim' };
  }
  const ids = new Set(recent.map((c) => c.id));
  const best = vectorHits.filter((h) => h.score >= threshold && ids.has(h.id)).sort((a, b) => b.score - a.score)[0];
  return best ? { id: best.id, reason: 'vector', score: best.score } : null;
}
