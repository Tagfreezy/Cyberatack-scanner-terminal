// Pure formatting helpers for Telegram HTML parse mode. No I/O here, so it's unit-testable.

import { muteTarget } from '../mutes';

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
  vendor?: string | null;
  first_seen?: number;
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
  darkreading: 'Dark Reading',
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

// ---------------------------------------------------------------------------------------
// Inline keyboard on alerts. callback_data is limited to 64 bytes: "info:<id>" / "mute:<id>".

export interface InlineKeyboard {
  inline_keyboard: { text: string; callback_data: string }[][];
}

export function alertKeyboard(inc: IncidentView): InlineKeyboard {
  const row = [{ text: 'ℹ️ More info', callback_data: `info:${inc.id}` }];
  const target = muteTarget({ attack_type: inc.attack_type, group_name: inc.group_name, vendor: inc.vendor, victim: inc.victim });
  if (target) row.push({ text: `🔇 Mute ${truncate(target.label, 24)} (7d)`, callback_data: `mute:${inc.id}` });
  return { inline_keyboard: [row] };
}

// ---------------------------------------------------------------------------------------
// Lists (digest, /latest, /today, weekly report)

const TYPE_ICON: Record<string, string> = {
  ransomware: '🔒',
  breach: '💧',
  ddos: '🌊',
  'zero-day': '🕳️',
  'supply-chain': '📦',
  wiper: '🧨',
  other: '⚠️',
};

export function typeIcon(t: string | null | undefined): string {
  return (t && TYPE_ICON[t]) || '⚠️';
}

/** One compact line: "🟠 🔒 <a>Title</a> 🇺🇸 · 3 src". */
export function formatIncidentLine(inc: IncidentView, maxTitle = 110): string {
  const sev = SEVERITY[Math.max(1, Math.min(5, Math.round(inc.severity)))]!.emoji;
  const title = escapeHtml(truncate(inc.title, maxTitle));
  const linked = inc.url ? `<a href="${escapeAttr(inc.url)}">${title}</a>` : title;
  const flag = countryFlag(inc.country);
  const src = inc.source_count > 1 ? ` · ${inc.source_count} src` : '';
  return `${sev} ${typeIcon(inc.attack_type)} ${linked}${flag ? ` ${flag}` : ''}${src}`;
}

/**
 * Split text into Telegram-sized messages on line boundaries. Telegram's limit is 4096 chars
 * of visible text; we count raw HTML (a superset) with margin, so a split never breaks a tag.
 */
export function splitMessage(text: string, max = 3800): string[] {
  const out: string[] = [];
  let cur = '';
  for (const line of text.split('\n')) {
    const piece = line.length > max ? line.slice(0, max - 1) + '…' : line;
    if (cur && cur.length + 1 + piece.length > max) {
      out.push(cur);
      cur = piece;
    } else {
      cur = cur ? `${cur}\n${piece}` : piece;
    }
  }
  if (cur) out.push(cur);
  return out;
}

export interface CountRow {
  key: string;
  cur: number;
  prev: number;
}

/** "▲ 40%" / "▼ 12%" / "new" / "=" trend marker, current vs previous period. */
export function trend(cur: number, prev: number): string {
  if (prev === 0) return cur > 0 ? '🆕' : '';
  const pct = Math.round(((cur - prev) / prev) * 100);
  if (pct === 0) return '＝';
  return pct > 0 ? `▲${pct}%` : `▼${-pct}%`;
}

function rankLines(rows: CountRow[], label: (k: string) => string): string[] {
  return rows.map((r, i) => `${i + 1}. ${label(r.key)} — <b>${r.cur}</b> ${trend(r.cur, r.prev)}`.trimEnd());
}

export interface DigestData {
  dateLabel: string; // e.g. "Tue 4 Nov"
  incidents: IncidentView[]; // sorted, most important first
  total: number; // may be > incidents.length (capped list)
}

export function formatDigest(d: DigestData): string {
  if (d.total === 0) {
    return `☀️ <b>CyberWatch daily digest</b> · ${escapeHtml(d.dateLabel)}\n\nQuiet 24 hours: nothing below your alert threshold.`;
  }
  const byType = new Map<string, number>();
  for (const i of d.incidents) byType.set(i.attack_type ?? 'other', (byType.get(i.attack_type ?? 'other') ?? 0) + 1);
  const mix = [...byType.entries()].sort((a, b) => b[1] - a[1]).map(([t, n]) => `${typeIcon(t)} ${n}`).join('  ');
  const lines = [
    `☀️ <b>CyberWatch daily digest</b> · ${escapeHtml(d.dateLabel)}`,
    `${d.total} incident${d.total === 1 ? '' : 's'} below your alert threshold in the last 24 h`,
    mix,
    '',
    ...d.incidents.map((i) => formatIncidentLine(i)),
  ];
  if (d.total > d.incidents.length) lines.push('', `…and ${d.total - d.incidents.length} more (see /today or the dashboard)`);
  return lines.join('\n');
}

export interface WeeklyData {
  rangeLabel: string;
  total: CountRow; // key unused
  bySeverity: { severity: number; n: number }[];
  byType: CountRow[];
  groups: CountRow[];
  sectors: CountRow[];
  countries: CountRow[];
  top: IncidentView[];
}

export function formatWeekly(w: WeeklyData, title = '📊 <b>CyberWatch weekly report</b>'): string {
  const sev = w.bySeverity
    .sort((a, b) => b.severity - a.severity)
    .map((s) => `${SEVERITY[s.severity]?.emoji ?? '⚪'} ${s.n}`)
    .join('  ');
  const lines = [
    `${title} · ${escapeHtml(w.rangeLabel)}`,
    '',
    `<b>${w.total.cur}</b> incidents (previous 7 days: ${w.total.prev}) ${trend(w.total.cur, w.total.prev)}`,
    sev,
  ];
  if (w.top.length) lines.push('', '<b>Top incidents</b>', ...w.top.map((i) => formatIncidentLine(i, 90)));
  if (w.byType.length) lines.push('', '<b>Attack types</b>', ...rankLines(w.byType, (k) => `${typeIcon(k)} ${escapeHtml(typeLabel(k))}`));
  if (w.groups.length) lines.push('', '<b>Most active ransomware groups</b>', ...rankLines(w.groups, (k) => `👾 ${escapeHtml(k)}`));
  if (w.sectors.length) lines.push('', '<b>Most targeted sectors</b>', ...rankLines(w.sectors, (k) => escapeHtml(k)));
  if (w.countries.length) {
    lines.push('', '<b>Most targeted countries</b>', ...rankLines(w.countries, (k) => `${countryFlag(k) || '🌍'} ${escapeHtml(k)}`));
  }
  return lines.join('\n');
}
