// SANS Internet Storm Center / DShield honeypot sensor data (https://isc.sans.edu/api/).
// Rules (checked 2026-11-03): best-effort API, no hard rate limit (back off 5 min on 429),
// descriptive User-Agent required ("default" UAs are blocked), data under CC BY-NC-SA 4.0:
// fine for personal use, and we credit "SANS ISC / DShield" wherever it's shown.
// The API has no spike endpoint, so spikes are computed here from daily top-port shares.

import type { Env } from '../types';

export const SANS_BASE = 'https://isc.sans.edu/api';
export const SANS_ATTRIBUTION = 'SANS ISC / DShield · CC BY-NC-SA 4.0';
// The ISC asks for contact info in the UA; per the owner's wish we use a descriptive project
// name without personal data.
export const SANS_UA = 'cyberwatch/1.0 (personal threat-monitoring dashboard)';

export interface PortRow {
  rank: number;
  port: number;
  records: number;
  targets: number;
  sources: number;
}

export interface SourceIpRow {
  ip: string;
  reports: number;
  targets: number;
}

export const PORT_SERVICE: Record<number, string> = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 81: 'HTTP-alt', 110: 'POP3',
  123: 'NTP', 135: 'MS-RPC', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 389: 'LDAP', 443: 'HTTPS',
  445: 'SMB', 502: 'Modbus', 1433: 'MSSQL', 1723: 'PPTP', 1883: 'MQTT', 1900: 'SSDP', 2222: 'SSH-alt',
  2323: 'Telnet-alt', 2375: 'Docker', 3306: 'MySQL', 3389: 'RDP', 5060: 'SIP', 5432: 'PostgreSQL',
  5555: 'ADB', 5900: 'VNC', 6379: 'Redis', 7547: 'TR-069', 8000: 'HTTP-alt', 8080: 'HTTP-proxy',
  8081: 'HTTP-alt', 8291: 'MikroTik', 8443: 'HTTPS-alt', 8888: 'HTTP-alt', 9000: 'HTTP-alt',
  9200: 'Elasticsearch', 10000: 'Webmin', 11211: 'Memcached', 27017: 'MongoDB', 37215: 'Huawei HG',
  49152: 'UPnP', 52869: 'UPnP/Realtek', 60001: 'IoT web',
};

export function serviceName(port: number): string {
  return PORT_SERVICE[port] ?? '';
}

async function sansGet(env: Env, path: string, timeoutMs = 25000): Promise<unknown> {
  const res = await fetch(`${SANS_BASE}/${path}${path.includes('?') ? '&' : '?'}json`, {
    headers: { 'User-Agent': SANS_UA, Accept: 'application/json' },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (res.status === 429) throw new Error('SANS ISC rate limit (429), backing off');
  if (!res.ok) throw new Error(`SANS ISC HTTP ${res.status} on ${path}`);
  const text = await res.text();
  if (!text.trim()) throw new Error(`SANS ISC empty response on ${path}`);
  return JSON.parse(text);
}

/** {"status":"green"} → "green". */
export function parseInfocon(d: unknown): string | null {
  const s = (d as { status?: unknown })?.status;
  return typeof s === 'string' && /^(green|yellow|orange|red)$/i.test(s) ? s.toLowerCase() : null;
}

/** topports returns {"0":{...},"1":{...},"date":"…","limit":N}; tolerate a plain array too. */
export function parseTopPorts(d: unknown): PortRow[] {
  const values = Array.isArray(d)
    ? d
    : Object.entries((d ?? {}) as Record<string, unknown>)
        .filter(([k]) => /^\d+$/.test(k))
        .map(([, v]) => v);
  return values
    .map((v) => v as Record<string, unknown>)
    .map((v) => ({
      rank: Number(v.rank) || 0,
      port: Number(v.targetport ?? v.port),
      records: Number(v.records) || 0,
      targets: Number(v.targets) || 0,
      sources: Number(v.sources) || 0,
    }))
    .filter((r) => Number.isInteger(r.port) && r.port >= 0 && r.port <= 65535)
    .sort((a, b) => b.records - a.records)
    .map((r, i) => ({ ...r, rank: i + 1 }));
}

export function parseTopIps(d: unknown): SourceIpRow[] {
  if (!Array.isArray(d)) return [];
  return d
    .map((v) => v as Record<string, unknown>)
    .filter((v) => typeof v.source === 'string')
    .map((v) => ({ ip: String(v.source).replace(/^0+(\d)/, '$1').replace(/\.0+(\d)/g, '.$1'), reports: Number(v.reports) || 0, targets: Number(v.targets) || 0 }));
}

export async function fetchInfocon(env: Env): Promise<string | null> {
  return parseInfocon(await sansGet(env, 'infocon'));
}

export async function fetchTopPorts(env: Env, date: string, n = 20): Promise<PortRow[]> {
  return parseTopPorts(await sansGet(env, `topports/records/${n}/${date}`));
}

export async function fetchTopIps(env: Env, n = 10): Promise<SourceIpRow[]> {
  // The dated form returns nothing (checked 2026-11-03); undated = today.
  return parseTopIps(await sansGet(env, `topips/records/${n}`));
}

// ---------------------------------------------------------------------------------------
// Spike detection (pure, unit-tested)

export interface Spike {
  port: number;
  service: string;
  rank: number;
  records: number;
  sources: number;
  share: number; // today's share of top-N records
  baseline: number; // average share over history days
  factor: number;
  isNew: boolean; // not in any history day's top N
}

const MIN_HISTORY_DAYS = 3;
const MIN_FACTOR = 3;
const MAX_RANK = 15;
const SHARE_FLOOR = 0.005; // a port that was ~absent counts as 0.5% so "new" ports need real volume

/**
 * Compare each port's share of today's top-N traffic with its average share over the history
 * days. Shares (not absolute counts) work intraday: today is incomplete, but proportions are
 * comparable. Needs enough history and enough of today to have elapsed (dayFraction).
 */
export function detectSpikes(today: PortRow[], history: PortRow[][], dayFraction: number): Spike[] {
  const days = history.filter((h) => h.length > 0);
  if (days.length < MIN_HISTORY_DAYS || !today.length) return [];
  const histTotal = days.reduce((a, d) => a + d.reduce((x, r) => x + r.records, 0), 0) / days.length;
  const todayTotal = today.reduce((x, r) => x + r.records, 0);
  // Too early in the UTC day for proportions to mean much.
  if (dayFraction < 0.2 || todayTotal < histTotal * 0.15) return [];

  const shareMaps = days.map((d) => {
    const total = d.reduce((x, r) => x + r.records, 0) || 1;
    return new Map(d.map((r) => [r.port, r.records / total]));
  });
  const spikes: Spike[] = [];
  for (const r of today) {
    if (r.rank > MAX_RANK) continue;
    const share = r.records / (todayTotal || 1);
    const seen = shareMaps.filter((m) => m.has(r.port));
    const baseline = shareMaps.reduce((a, m) => a + (m.get(r.port) ?? 0), 0) / shareMaps.length;
    const factor = share / Math.max(baseline, SHARE_FLOOR);
    if (factor >= MIN_FACTOR) {
      spikes.push({
        port: r.port,
        service: serviceName(r.port),
        rank: r.rank,
        records: r.records,
        sources: r.sources,
        share,
        baseline,
        factor: Math.round(factor * 10) / 10,
        isNew: seen.length === 0,
      });
    }
  }
  return spikes.sort((a, b) => b.factor - a.factor);
}
