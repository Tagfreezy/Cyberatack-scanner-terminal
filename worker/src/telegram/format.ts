// Pure formatting helpers for Telegram HTML parse mode. No I/O here, so it's unit-testable.

export interface IncidentView {
  id: number;
  title: string;
  summary: string | null;
  url: string | null;
  attack_type: string | null;
  sector: string | null;
  country: string | null;
  severity: number;
  source_count: number;
  sources: string | null; // JSON array
  group_name?: string | null;
  victim?: string | null;
}

/** Escape for Telegram HTML: only &, <, > (and " inside attributes) are special. */
export function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export function escapeAttr(s: string): string {
  return escapeHtml(s).replace(/"/g, '&quot;');
}

export const SEVERITY: Record<number, { emoji: string; label: string }> = {
  5: { emoji: '🔴', label: 'CRITICAL' },
  4: { emoji: '🟠', label: 'HIGH' },
  3: { emoji: '🟡', label: 'MEDIUM' },
  2: { emoji: '🔵', label: 'LOW' },
  1: { emoji: '⚪', label: 'INFO' },
};

export function severityBadge(sev: number): string {
  const s = SEVERITY[Math.max(1, Math.min(5, Math.round(sev)))]!;
  return `${s.emoji} <b>${s.label}</b>`;
}

/** ISO-3166 alpha-2 → flag emoji via regional indicator symbols. */
export function countryFlag(code: string | null | undefined): string {
  if (!code) return '';
  let c = code.trim().toUpperCase();
  if (c === 'UK') c = 'GB';
  if (!/^[A-Z]{2}$/.test(c)) return '';
  return String.fromCodePoint(...[...c].map((ch) => 0x1f1e6 + ch.charCodeAt(0) - 65));
}

const TYPE_LABEL: Record<string, string> = {
  ransomware: 'Ransomware',
  breach: 'Data breach',
  ddos: 'DDoS',
  'zero-day': 'Zero-day / exploited vuln',
  'supply-chain': 'Supply chain',
  wiper: 'Wiper',
  other: 'Other',
};

export function typeLabel(t: string | null | undefined): string {
  return (t && TYPE_LABEL[t]) || 'Other';
}

function truncate(s: string, n: number): string {
  return s.length <= n ? s : `${s.slice(0, n - 1).trimEnd()}…`;
}

const SOURCE_LABEL: Record<string, string> = {
  bleepingcomputer: 'BleepingComputer',
  therecord: 'The Record',
  thehackernews: 'The Hacker News',
  securityweek: 'SecurityWeek',
  'cisa-kev': 'CISA KEV',
  'ransomware.live': 'ransomware.live',
};

export function sourceLabel(s: string): string {
  return SOURCE_LABEL[s] ?? s;
}

/** Instant alert message. Kept well under Telegram's 4096-char limit. */
export function formatAlert(inc: IncidentView): string {
  const lines: string[] = [];
  lines.push(`${severityBadge(inc.severity)} · ${escapeHtml(typeLabel(inc.attack_type))}`);
  lines.push(`<b>${escapeHtml(truncate(inc.title, 300))}</b>`);
  if (inc.summary) lines.push(escapeHtml(truncate(inc.summary, 600)));

  const facts: string[] = [];
  if (inc.group_name) facts.push(`👾 ${escapeHtml(inc.group_name)}`);
  if (inc.sector) facts.push(`🏢 ${escapeHtml(inc.sector)}`);
  if (inc.country) {
    const flag = countryFlag(inc.country);
    facts.push(`${flag || '🌍'} ${escapeHtml(inc.country.toUpperCase())}`);
  }
  if (facts.length) lines.push(facts.join(' · '));

  let srcNames: string[] = [];
  try {
    srcNames = inc.sources ? (JSON.parse(inc.sources) as string[]) : [];
  } catch {
    /* ignore */
  }
  const n = Math.max(inc.source_count, 1);
  const names = srcNames.length ? ` (${escapeHtml(srcNames.map(sourceLabel).join(', '))})` : '';
  lines.push(`📰 ${n} source${n === 1 ? '' : 's'}${names}`);

  if (inc.url) lines.push(`🔗 <a href="${escapeAttr(inc.url)}">Read more</a>`);
  return lines.join('\n');
}
