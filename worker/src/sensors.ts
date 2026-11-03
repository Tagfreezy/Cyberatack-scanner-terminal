import { log } from './log';
import { queueTextStatements } from './reports';
import {
  SANS_ATTRIBUTION,
  detectSpikes,
  fetchInfocon,
  fetchTopIps,
  fetchTopPorts,
  serviceName,
  type PortRow,
  type SourceIpRow,
  type Spike,
} from './sources/sans';
import { escapeHtml } from './telegram/format';
import { loadToggles } from './toggles';
import type { Env } from './types';

// Hourly SANS ISC job: infocon + today's top ports + top sources, a 9-day top-port history
// (for spike detection), the dashboard snapshot, and Telegram alerts for spikes / infocon.
// Subrequests per run: ≤ 3 + 1 (yesterday) + 2 (backfill) fetches, ~4 D1.

const DAY = 86_400_000;
const HISTORY_DAYS = 7;
const BACKFILL_PER_RUN = 2;
const SPIKE_REALERT_MS = DAY;

interface DayData {
  complete: boolean;
  ports: PortRow[];
}
type History = Record<string, DayData>;

export interface SensorsSnapshot {
  available: true;
  updated_at: number;
  date: string;
  infocon: string | null;
  top_ports: (PortRow & { service: string })[];
  top_sources: SourceIpRow[];
  spikes: Spike[];
  history_days: number;
  attribution: string;
}

const utcDate = (ts: number) => new Date(ts).toISOString().slice(0, 10);

export function formatSpikeAlert(spikes: Spike[]): string {
  const lines = ['📡 <b>Port spike on SANS ISC honeypot sensors</b>', ''];
  for (const s of spikes.slice(0, 5)) {
    const svc = s.service ? ` (${escapeHtml(s.service)})` : '';
    const why = s.isNew ? 'new in the top ports' : `${s.factor}× its usual share`;
    lines.push(
      `• <b>${s.port}</b>${svc}: ${why} · rank ${s.rank} · ${s.records.toLocaleString('en-US')} reports from ${s.sources.toLocaleString('en-US')} sources`,
    );
  }
  lines.push('', 'A sudden jump often means a new exploit or botnet is scanning for that service.', `<i>${SANS_ATTRIBUTION}</i>`);
  return lines.join('\n');
}

export function formatInfoconAlert(prev: string, cur: string): string {
  const icon: Record<string, string> = { green: '🟢', yellow: '🟡', orange: '🟠', red: '🔴' };
  const msg =
    cur === 'green'
      ? 'Back to normal.'
      : 'The ISC raises the Infocon when a significant new threat is spreading on the internet. Check isc.sans.edu for the diary entry.';
  return `🛡️ <b>SANS ISC Infocon: ${icon[prev] ?? ''} ${prev.toUpperCase()} → ${icon[cur] ?? ''} ${cur.toUpperCase()}</b>\n\n${msg}\n<i>${SANS_ATTRIBUTION}</i>`;
}

export async function runSensors(env: Env, now = Date.now()): Promise<{ spikes: number; infocon: string | null }> {
  const today = utcDate(now);
  const yesterday = utcDate(now - DAY);

  const { results } = await env.DB.prepare(
    "SELECT key, value FROM settings WHERE key IN ('sans_history', 'sensors_snapshot', 'spike_alerted')",
  ).all<{ key: string; value: string }>();
  const get = <T>(k: string, fallback: T): T => {
    const v = results.find((r) => r.key === k)?.value;
    try {
      return v ? (JSON.parse(v) as T) : fallback;
    } catch {
      return fallback;
    }
  };
  const history = get<History>('sans_history', {});
  const prevSnap = get<Partial<SensorsSnapshot>>('sensors_snapshot', {});
  const alerted = get<Record<string, number>>('spike_alerted', {});

  // Complete past days we still need: yesterday's final numbers + backfill for the window.
  const need: string[] = [];
  if (!history[yesterday]?.complete) need.push(yesterday);
  for (let d = 2; d <= HISTORY_DAYS + 1 && need.length < 1 + BACKFILL_PER_RUN; d++) {
    const date = utcDate(now - d * DAY);
    if (!history[date]?.complete) need.push(date);
  }

  const [infoconR, todayR, ipsR, ...pastR] = await Promise.allSettled([
    fetchInfocon(env),
    fetchTopPorts(env, today),
    fetchTopIps(env),
    ...need.map((d) => fetchTopPorts(env, d)),
  ]);
  if (todayR.status === 'rejected' && infoconR.status === 'rejected') {
    throw new Error(`SANS ISC unreachable: ${String((todayR as PromiseRejectedResult).reason)}`);
  }

  if (todayR.status === 'fulfilled') history[today] = { complete: false, ports: todayR.value };
  need.forEach((d, i) => {
    const r = pastR[i];
    if (r?.status === 'fulfilled' && r.value.length) history[d] = { complete: true, ports: r.value };
  });
  // Keep the window small (one settings row, ~8 KB).
  for (const d of Object.keys(history)) if (d < utcDate(now - (HISTORY_DAYS + 2) * DAY)) delete history[d];

  const todayPorts = history[today]?.ports ?? prevSnap.top_ports ?? [];
  const past = Array.from({ length: HISTORY_DAYS }, (_, i) => history[utcDate(now - (i + 1) * DAY)])
    .filter((d): d is DayData => !!d?.complete)
    .map((d) => d.ports);
  const dayFraction = (now - Date.parse(`${today}T00:00:00Z`)) / DAY;
  const spikes = detectSpikes(todayPorts, past, dayFraction);

  const infocon = infoconR.status === 'fulfilled' ? infoconR.value : (prevSnap.infocon ?? null);
  const snapshot: SensorsSnapshot = {
    available: true,
    updated_at: now,
    date: today,
    infocon,
    top_ports: todayPorts.slice(0, 15).map((p) => ({ ...p, service: serviceName(p.port) })),
    top_sources: ipsR.status === 'fulfilled' ? ipsR.value.slice(0, 10) : (prevSnap.top_sources ?? []),
    spikes,
    history_days: past.length,
    attribution: SANS_ATTRIBUTION,
  };

  // ---- alerts --------------------------------------------------------------------------
  const toggles = await loadToggles(env);
  const quiet = await env.DB.prepare("SELECT 1 AS q FROM mutes WHERE kind = 'all' AND (until IS NULL OR until > ?) LIMIT 1")
    .bind(now)
    .first<{ q: number }>();
  const messages: string[] = [];
  if (toggles.infocon && prevSnap.infocon && infocon && prevSnap.infocon !== infocon) {
    messages.push(formatInfoconAlert(prevSnap.infocon, infocon)); // sent even in quiet time: rare and important
  }
  const fresh = spikes.filter((s) => (alerted[String(s.port)] ?? 0) < now - SPIKE_REALERT_MS);
  if (toggles.spikes && fresh.length && !quiet) {
    messages.push(formatSpikeAlert(fresh));
    for (const s of fresh) alerted[String(s.port)] = now;
  }
  for (const k of Object.keys(alerted)) if (alerted[k]! < now - 7 * DAY) delete alerted[k];

  const upsert = (key: string, value: unknown) =>
    env.DB.prepare('INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2').bind(key, JSON.stringify(value));
  await env.DB.batch([
    upsert('sans_history', history),
    upsert('sensors_snapshot', snapshot),
    upsert('spike_alerted', alerted),
    ...queueTextStatements(env, messages, now),
    env.DB.prepare(
      `INSERT INTO source_state (source, initialized, last_run, last_ok, last_fetched, last_new) VALUES ('sans-isc', 1, ?1, ?1, ?2, ?3)
       ON CONFLICT(source) DO UPDATE SET last_run = ?1, last_ok = ?1, last_fetched = ?2, last_new = ?3`,
    ).bind(now, todayPorts.length, spikes.length),
  ]);
  log('sensors', { ok: true, infocon, ports: todayPorts.length, history: past.length, spikes: spikes.map((s) => s.port), alerts: messages.length });
  return { spikes: spikes.length, infocon };
}
