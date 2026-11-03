import { AiQuotaError, explainIncident } from '../ai';
import { getThreshold, setSetting } from '../db';
import { logError } from '../log';
import { BUTTON_MUTE_MS, loadMutes, muteTarget, type Mute } from '../mutes';
import { INCIDENT_COLS, buildWeekly, dateLabel, weeklyMessages } from '../reports';
import { formatDuration, localMidnight, parseDuration } from '../time';
import type { Env } from '../types';
import { sendMessage, tg } from './api';
import {
  escapeHtml,
  formatIncidentLine,
  sourceLabel,
  splitMessage,
  trend,
  typeIcon,
  typeLabel,
  type IncidentView,
} from './format';

// Bot commands. Each returns the HTML text(s) to send; webhook.ts does the sending.

export const BOT_COMMANDS = [
  { command: 'latest', description: 'Latest incidents (e.g. /latest 20)' },
  { command: 'today', description: 'Everything since midnight' },
  { command: 'stats', description: 'Counts today and this week' },
  { command: 'week', description: 'Weekly report (last 7 days)' },
  { command: 'mute', description: 'Quiet time, e.g. /mute 2h' },
  { command: 'unmute', description: 'End quiet time and all mutes' },
  { command: 'settings', description: 'Threshold, mutes, schedule' },
  { command: 'threshold', description: 'Instant-alert level 1-5' },
  { command: 'status', description: 'Source health' },
  { command: 'help', description: 'All commands' },
];

export const HELP = [
  '<b>CyberWatch</b> — live cyberattack monitor',
  '',
  '/latest [n] — newest incidents',
  '/today — everything since midnight',
  '/stats — counts today and this week',
  '/week — weekly report (last 7 days)',
  '/mute 2h — quiet time (30m, 2h, 1d…); held alerts go to the digest',
  '/unmute — end quiet time and all group/vendor mutes',
  '/settings — threshold, mutes, schedule',
  '/threshold 4 — instant alerts at this severity and above (1-5)',
  '/status — source health',
  '',
  'Buttons on each alert: <b>More info</b> (AI explanation) and <b>Mute</b> (that ransomware group or vendor, 7 days).',
  'Daily digest 08:00 and weekly report Monday 08:00 (Europe/Zurich).',
].join('\n');

const timeFmt = (ts: number, tz: string) =>
  new Intl.DateTimeFormat('en-GB', { timeZone: tz, hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).format(new Date(ts));

function ago(ms: number): string {
  const m = Math.max(0, Math.round((Date.now() - ms) / 60000));
  if (m < 60) return `${m}m`;
  const h = Math.round(m / 60);
  return h < 48 ? `${h}h` : `${Math.round(h / 24)}d`;
}

export async function cmdLatest(env: Env, arg?: string): Promise<string[]> {
  const n = Math.max(1, Math.min(25, Number(arg) || 10));
  const { results } = await env.DB.prepare(
    `SELECT ${INCIDENT_COLS} FROM incidents WHERE alert_state != 'baseline' ORDER BY first_seen DESC, id DESC LIMIT ?`,
  )
    .bind(n)
    .all<IncidentView & { first_seen: number }>();
  if (!results.length) return ['No incidents yet. New ones appear here as sources report them.'];
  const lines = [`<b>Latest ${results.length} incidents</b>`, ''];
  for (const i of results) lines.push(`${formatIncidentLine(i, 90)} · ${ago(i.first_seen)}`);
  return splitMessage(lines.join('\n'));
}

export async function cmdToday(env: Env): Promise<string[]> {
  const since = localMidnight(Date.now(), env.TIMEZONE);
  const [list, counts] = await env.DB.batch([
    env.DB.prepare(
      `SELECT ${INCIDENT_COLS} FROM incidents WHERE first_seen >= ? AND alert_state != 'baseline'
       ORDER BY severity DESC, source_count DESC, first_seen DESC LIMIT 30`,
    ).bind(since),
    env.DB.prepare(
      `SELECT COALESCE(attack_type, 'other') AS t, COUNT(*) AS n FROM incidents
       WHERE first_seen >= ? AND alert_state != 'baseline' GROUP BY 1 ORDER BY n DESC`,
    ).bind(since),
  ]);
  const rows = list!.results as unknown as IncidentView[];
  const byType = counts!.results as { t: string; n: number }[];
  const total = byType.reduce((a, r) => a + r.n, 0);
  if (!total) return [`<b>Today</b> (${escapeHtml(dateLabel(Date.now(), env.TIMEZONE))})\n\nNothing yet today.`];
  const lines = [
    `<b>Today</b> (${escapeHtml(dateLabel(Date.now(), env.TIMEZONE))}): ${total} incident${total === 1 ? '' : 's'}`,
    byType.map((r) => `${typeIcon(r.t)} ${r.n}`).join('  '),
    '',
    ...rows.map((i) => formatIncidentLine(i, 90)),
  ];
  if (total > rows.length) lines.push('', `…and ${total - rows.length} more.`);
  return splitMessage(lines.join('\n'));
}

export async function cmdStats(env: Env): Promise<string[]> {
  const now = Date.now();
  const today = localMidnight(now, env.TIMEZONE);
  const [w, t] = await Promise.all([
    buildWeekly(env, now),
    env.DB.prepare(
      `SELECT COUNT(*) AS n, COALESCE(SUM(severity >= 4), 0) AS high FROM incidents WHERE first_seen >= ? AND alert_state != 'baseline'`,
    )
      .bind(today)
      .first<{ n: number; high: number }>(),
  ]);
  const top = (rows: { key: string; cur: number }[], fmt: (k: string) => string) =>
    rows.length ? rows.map((r) => `${fmt(r.key)} ${r.cur}`).join(' · ') : '—';
  return [
    [
      '<b>CyberWatch stats</b>',
      '',
      `Today: <b>${t?.n ?? 0}</b> incidents (${t?.high ?? 0} high/critical)`,
      `Last 7 days: <b>${w.total.cur}</b> ${trend(w.total.cur, w.total.prev)} (previous 7: ${w.total.prev})`,
      '',
      `<b>By type (7d)</b>: ${top(w.byType, (k) => `${typeIcon(k)} ${escapeHtml(typeLabel(k))}`)}`,
      `<b>Ransomware groups</b>: ${top(w.groups, (k) => escapeHtml(k))}`,
      `<b>Sectors</b>: ${top(w.sectors, (k) => escapeHtml(k))}`,
      `<b>Countries</b>: ${top(w.countries, (k) => escapeHtml(k))}`,
    ].join('\n'),
  ];
}

export async function cmdWeek(env: Env): Promise<string[]> {
  return weeklyMessages(env, Date.now(), '📊 <b>Last 7 days</b>');
}

export async function cmdMute(env: Env, arg?: string): Promise<string[]> {
  const ms = parseDuration(arg);
  if (!ms) return ['Usage: <code>/mute 2h</code> (also 30m, 1d, 1w; max 30 days). Use /unmute to end it early.'];
  const until = Date.now() + ms;
  // One global quiet time at a time: replace any existing one.
  await env.DB.batch([
    env.DB.prepare("DELETE FROM mutes WHERE kind = 'all'"),
    env.DB.prepare("INSERT INTO mutes (kind, value, until, created_at) VALUES ('all', NULL, ?, ?)").bind(until, Date.now()),
  ]);
  return [
    `🔕 Quiet for ${formatDuration(ms)} (until ${timeFmt(until, env.TIMEZONE)}). Alerts are held and land in the next daily digest. /unmute ends it early.`,
  ];
}

function describeMute(m: Mute, tz: string): string {
  const until = m.until ? `until ${dateLabel(m.until, tz)} ${timeFmt(m.until, tz)}` : 'forever';
  if (m.kind === 'all') return `🔕 quiet time ${until}`;
  return `🔇 ${m.kind} <b>${escapeHtml(m.value ?? '')}</b> ${until}`;
}

export async function cmdUnmute(env: Env, arg?: string): Promise<string[]> {
  const mutes = await loadMutes(env.DB);
  const needle = arg?.trim().toLowerCase();
  const targets = needle ? mutes.filter((m) => m.value?.includes(needle)) : mutes;
  if (!targets.length) return [needle ? `No active mute matches "${escapeHtml(needle)}". See /settings.` : 'Nothing is muted.'];
  await env.DB.prepare(`DELETE FROM mutes WHERE id IN (${targets.map(() => '?').join(',')})`)
    .bind(...targets.map((m) => m.id))
    .run();
  return [`🔔 Unmuted:\n${targets.map((m) => describeMute(m, env.TIMEZONE)).join('\n')}`];
}

export async function cmdThreshold(env: Env, arg?: string): Promise<string[]> {
  const n = Number(arg);
  if (!Number.isInteger(n) || n < 1 || n > 5) {
    return [`Current instant-alert threshold: <b>${await getThreshold(env)}</b>. Usage: <code>/threshold 4</code> (1 = everything … 5 = only critical).`];
  }
  await setSetting(env.DB, 'threshold', String(n));
  return [`✅ Instant alerts now for severity <b>${n}</b> and above. Everything below goes to the 08:00 digest.`];
}

export async function cmdSettings(env: Env): Promise<string[]> {
  const [threshold, mutes, paused] = await Promise.all([
    getThreshold(env),
    loadMutes(env.DB),
    env.DB.prepare("SELECT value FROM settings WHERE key = 'ai_paused_until'").first<{ value: string }>(),
  ]);
  const aiPaused = Number(paused?.value ?? 0) > Date.now();
  return [
    [
      '<b>Settings</b>',
      '',
      `Instant alerts: severity ≥ <b>${threshold}</b> (/threshold)`,
      `Daily digest: 08:00 · weekly report: Monday 08:00 (${escapeHtml(env.TIMEZONE)})`,
      `AI classification: ${aiPaused ? '🟠 paused (quota), keyword fallback' : '🟢 on'} · ${escapeHtml(env.AI_MODEL.split('/').pop() ?? '')}`,
      '',
      '<b>Mutes</b>',
      ...(mutes.length ? mutes.map((m) => describeMute(m, env.TIMEZONE)) : ['none']),
      '',
      '<b>Sources</b>',
      'Dark Reading, The Record, The Hacker News, SecurityWeek, CISA KEV, ransomware.live',
      'Optional (phase 5): SANS ISC sensors, Mastodon, ThreatFox: off',
    ].join('\n'),
  ];
}

// ---------------------------------------------------------------------------------------
// Inline-button callbacks

/** Acknowledge a button press. Non-fatal: if Telegram rejects it (e.g. the query timed out),
 * the actual reply should still be sent. */
async function answerCallback(env: Env, body: { callback_query_id: string; text?: string; show_alert?: boolean }): Promise<void> {
  try {
    await tg(env, 'answerCallbackQuery', body);
  } catch (err) {
    logError('callback.answer', err);
  }
}

interface CallbackIncident {
  id: number;
  title: string;
  summary: string | null;
  attack_type: string | null;
  victim: string | null;
  sector: string | null;
  country: string | null;
  group_name: string | null;
  vendor: string | null;
  details: string | null;
}

async function loadCallbackIncident(env: Env, id: number): Promise<CallbackIncident | null> {
  return env.DB.prepare(
    'SELECT id, title, summary, attack_type, victim, sector, country, group_name, vendor, details FROM incidents WHERE id = ?',
  )
    .bind(id)
    .first<CallbackIncident>();
}

export async function onMoreInfo(env: Env, callbackId: string, incidentId: number, replyTo?: number): Promise<void> {
  const inc = await loadCallbackIncident(env, incidentId);
  if (!inc) {
    await answerCallback(env, { callback_query_id: callbackId, text: 'Incident no longer exists.' });
    return;
  }
  // Answer the button right away (Telegram shows a spinner until we do), then think.
  await answerCallback(env, { callback_query_id: callbackId, text: inc.details ? '' : 'Writing a short explanation…' });

  const { results: reports } = await env.DB.prepare(
    'SELECT source, title, summary, url FROM items WHERE incident_id = ? ORDER BY created_at LIMIT 4',
  )
    .bind(incidentId)
    .all<{ source: string; title: string; summary: string | null; url: string | null }>();

  let details = inc.details;
  if (!details) {
    try {
      details = await explainIncident(env, inc, reports);
      if (details) await env.DB.prepare('UPDATE incidents SET details = ? WHERE id = ?').bind(details, incidentId).run();
    } catch (err) {
      if (!(err instanceof AiQuotaError)) logError('ai.explain', err, { incident: incidentId });
    }
  }
  const body = details
    ? escapeHtml(details).replace(/^(What happened|Who is affected|Why it matters):/gm, '<b>$1:</b>')
    : `<i>AI explanation unavailable right now. What the sources say:</i>\n${reports
        .map((r) => `• ${escapeHtml(r.summary?.slice(0, 300) || r.title)}`)
        .join('\n')}`;
  const links = reports
    .filter((r) => r.url)
    .map((r) => `<a href="${escapeHtml(r.url!).replace(/"/g, '&quot;')}">${escapeHtml(sourceLabel(r.source))}</a>`)
    .join(' · ');
  await sendMessage(env, `ℹ️ <b>${escapeHtml(inc.title)}</b>\n\n${body}${links ? `\n\n📰 ${links}` : ''}`, {
    ...(replyTo ? { reply_parameters: { message_id: replyTo, allow_sending_without_reply: true } } : {}),
  });
}

export async function onMute(env: Env, callbackId: string, incidentId: number): Promise<void> {
  const inc = await loadCallbackIncident(env, incidentId);
  const target = inc ? muteTarget(inc) : null;
  if (!target) {
    await answerCallback(env, { callback_query_id: callbackId, text: 'Nothing to mute for this incident.' });
    return;
  }
  const until = Date.now() + BUTTON_MUTE_MS;
  // Re-muting the same target just extends it.
  await env.DB.batch([
    env.DB.prepare('DELETE FROM mutes WHERE kind = ? AND value = ?').bind(target.kind, target.value),
    env.DB.prepare('INSERT INTO mutes (kind, value, until, created_at) VALUES (?, ?, ?, ?)').bind(target.kind, target.value, until, Date.now()),
  ]);
  await answerCallback(env, {
    callback_query_id: callbackId,
    text: `🔇 ${target.label} muted for 7 days. /unmute ${target.value} to undo.`,
    show_alert: false,
  });
}
