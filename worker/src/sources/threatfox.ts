// Optional: abuse.ch ThreatFox (OFF by default, /toggle threatfox; needs a free Auth-Key from
// https://auth.abuse.ch). ThreatFox lists IOCs (C2 servers, payload URLs…), not victims, so it
// feeds a "malware families" panel rather than incidents.
//
// The 24 h IOC dump can be several MB of JSON: parsing it would blow the free plan's CPU
// budget. We stream only the first ~600 KB (newest IOCs) and count families with a regex.

import type { Env } from '../types';

const API = 'https://threatfox-api.abuse.ch/api/v1/';
const MAX_BYTES = 600 * 1024;

export interface ThreatFoxSnapshot {
  updated_at: number;
  sampled: number; // IOCs counted (newest first, capped by MAX_BYTES)
  families: { name: string; n: number }[];
  types: { name: string; n: number }[];
}

/** Count malware families + threat types in a (possibly truncated) get_iocs response. Pure. */
export function countIocs(text: string): Omit<ThreatFoxSnapshot, 'updated_at'> {
  const fam = new Map<string, number>();
  const typ = new Map<string, number>();
  let sampled = 0;
  for (const m of text.matchAll(/"malware_printable"\s*:\s*"([^"]*)"/g)) {
    sampled++;
    const name = m[1]!.trim() || 'Unknown';
    fam.set(name, (fam.get(name) ?? 0) + 1);
  }
  for (const m of text.matchAll(/"threat_type"\s*:\s*"([^"]*)"/g)) typ.set(m[1]!, (typ.get(m[1]!) ?? 0) + 1);
  const top = (m: Map<string, number>, n: number) =>
    [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([name, n]) => ({ name, n }));
  return { sampled, families: top(fam, 8), types: top(typ, 5) };
}

export async function runThreatFox(env: Env, now = Date.now()): Promise<ThreatFoxSnapshot> {
  if (!env.THREATFOX_AUTH_KEY) throw new Error('THREATFOX_AUTH_KEY not set');
  const res = await fetch(API, {
    method: 'POST',
    headers: { 'Auth-Key': env.THREATFOX_AUTH_KEY, 'User-Agent': env.USER_AGENT, 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: 'get_iocs', days: 1 }),
    signal: AbortSignal.timeout(25000),
  });
  if (res.status === 401 || res.status === 403) throw new Error(`ThreatFox ${res.status}: Auth-Key rejected`);
  if (!res.ok || !res.body) throw new Error(`ThreatFox HTTP ${res.status}`);

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let text = '';
  try {
    while (text.length < MAX_BYTES) {
      const { done, value } = await reader.read();
      if (done) break;
      text += decoder.decode(value, { stream: true });
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  if (/"query_status"\s*:\s*"(?!ok)/.test(text.slice(0, 200))) throw new Error(`ThreatFox: ${text.slice(0, 120)}`);

  const snap: ThreatFoxSnapshot = { updated_at: now, ...countIocs(text) };
  await env.DB.batch([
    env.DB.prepare("INSERT INTO settings (key, value) VALUES ('threatfox_snapshot', ?1) ON CONFLICT(key) DO UPDATE SET value = ?1").bind(
      JSON.stringify(snap),
    ),
    env.DB.prepare(
      `INSERT INTO source_state (source, initialized, last_run, last_ok, last_fetched) VALUES ('threatfox', 1, ?1, ?1, ?2)
       ON CONFLICT(source) DO UPDATE SET last_run = ?1, last_ok = ?1, last_fetched = ?2`,
    ).bind(now, snap.sampled),
  ]);
  return snap;
}
