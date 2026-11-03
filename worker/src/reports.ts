import { formatDigest, formatWeekly, splitMessage, type CountRow, type IncidentView, type WeeklyData } from './telegram/format';
import { isoWeekKey, localParts } from './time';
import type { Env } from './types';

// Report queries. Aggregation happens in SQL (GROUP BY), not in JS, to keep Worker CPU low.
// "baseline" incidents (silently imported on day one) are excluded from lists and stats.

export const INCIDENT_COLS =
  'id, title, summary, url, attack_type, sector, country, severity, source_count, sources, group_name, victim, vendor, first_seen';

const DAY = 86_400_000;

export function dateLabel(ts: number, timeZone: string): string {
  return new Intl.DateTimeFormat('en-GB', { timeZone, weekday: 'short', day: 'numeric', month: 'short' }).format(new Date(ts));
}

/** Daily digest: everything below the alert threshold not yet digested (incl. alerts held by /mute). */
export async function buildDigest(env: Env, now = Date.now()): Promise<{ messages: string[]; ids: number[] }> {
  const where = "alert_state = 'digest' AND digested_at IS NULL AND first_seen > ?";
  const since = now - 36 * 3600_000; // a missed day doesn't produce a giant digest
  const [list, all] = await env.DB.batch([
    env.DB.prepare(
      `SELECT ${INCIDENT_COLS} FROM incidents WHERE ${where} ORDER BY severity DESC, source_count DESC, first_seen DESC LIMIT 40`,
    ).bind(since),
    env.DB.prepare(`SELECT id FROM incidents WHERE ${where}`).bind(since),
  ]);
  const incidents = list!.results as unknown as IncidentView[];
  const ids = (all!.results as { id: number }[]).map((r) => r.id);
  const text = formatDigest({ dateLabel: dateLabel(now, env.TIMEZONE), incidents, total: ids.length });
  return { messages: splitMessage(text), ids };
}

function countRowsQuery(env: Env, keyExpr: string, extraWhere: string, limit: number, groupBy = '1'): D1PreparedStatement {
  return env.DB.prepare(
    `SELECT ${keyExpr} AS key, SUM(first_seen >= ?2) AS cur, SUM(first_seen < ?2) AS prev
     FROM incidents
     WHERE first_seen >= ?1 AND first_seen < ?3 AND alert_state != 'baseline' ${extraWhere}
     GROUP BY ${groupBy} HAVING cur > 0 ORDER BY cur DESC, prev DESC LIMIT ${limit}`,
  );
}

/** Last 7 days ending at `end`, compared with the 7 days before. */
export async function buildWeekly(env: Env, end = Date.now()): Promise<WeeklyData> {
  const curStart = end - 7 * DAY;
  const prevStart = end - 14 * DAY;
  const b = (s: D1PreparedStatement) => s.bind(prevStart, curStart, end);
  const res = await env.DB.batch([
    b(
      env.DB.prepare(
        `SELECT 'all' AS key, COALESCE(SUM(first_seen >= ?2), 0) AS cur, COALESCE(SUM(first_seen < ?2), 0) AS prev
         FROM incidents WHERE first_seen >= ?1 AND first_seen < ?3 AND alert_state != 'baseline'`,
      ),
    ),
    env.DB.prepare(
      `SELECT severity, COUNT(*) AS n FROM incidents
       WHERE first_seen >= ?1 AND first_seen < ?2 AND alert_state != 'baseline' GROUP BY severity`,
    ).bind(curStart, end),
    b(countRowsQuery(env, "COALESCE(attack_type, 'other')", '', 7)),
    // Group names vary in case between sources ("Akira" / "akira"): group case-insensitively.
    b(countRowsQuery(env, 'MAX(group_name)', 'AND group_name IS NOT NULL', 5, 'lower(group_name)')),
    b(countRowsQuery(env, 'sector', "AND sector IS NOT NULL AND sector != 'Other'", 5)),
    b(countRowsQuery(env, 'country', 'AND country IS NOT NULL', 5)),
    env.DB.prepare(
      `SELECT ${INCIDENT_COLS} FROM incidents
       WHERE first_seen >= ?1 AND first_seen < ?2 AND alert_state != 'baseline'
       ORDER BY severity DESC, source_count DESC, first_seen DESC LIMIT 5`,
    ).bind(curStart, end),
  ]);
  const rows = (i: number) => res[i]!.results as unknown as CountRow[];
  return {
    rangeLabel: `${dateLabel(curStart, env.TIMEZONE)} – ${dateLabel(end - 1, env.TIMEZONE)}`,
    total: rows(0)[0] ?? { key: 'all', cur: 0, prev: 0 },
    bySeverity: res[1]!.results as { severity: number; n: number }[],
    byType: rows(2),
    groups: rows(3),
    sectors: rows(4),
    countries: rows(5),
    top: res[6]!.results as unknown as IncidentView[],
  };
}

export async function weeklyMessages(env: Env, end = Date.now(), title?: string): Promise<string[]> {
  return splitMessage(formatWeekly(await buildWeekly(env, end), title));
}

/** Queue messages in the outbox so they respect Telegram's rate limit like alerts do. */
export function queueTextStatements(env: Env, messages: string[], now = Date.now()): D1PreparedStatement[] {
  return messages.map((text) =>
    env.DB.prepare("INSERT INTO outbox (kind, payload, next_attempt_at, created_at) VALUES ('text', ?, ?, ?)").bind(
      JSON.stringify({ text }),
      now,
      now,
    ),
  );
}

/**
 * Called every tick. Sends the daily digest during the 08:xx local hour (once per local date)
 * and the weekly report on Mondays in the same hour (once per ISO week). Any tick in that
 * hour works, so a single missed or failed tick doesn't skip a day. DST-safe (see time.ts).
 */
export async function maybeSendReports(env: Env, scheduledTime: number): Promise<string[]> {
  const local = localParts(scheduledTime, env.TIMEZONE);
  if (local.hour !== 8) return [];
  const { results } = await env.DB.prepare("SELECT key, value FROM settings WHERE key IN ('last_digest', 'last_weekly')").all<{
    key: string;
    value: string;
  }>();
  const get = (k: string) => results.find((r) => r.key === k)?.value;
  const sent: string[] = [];
  const now = Date.now();
  const stmts: D1PreparedStatement[] = [];

  if (get('last_digest') !== local.date) {
    const digest = await buildDigest(env, now);
    stmts.push(...queueTextStatements(env, digest.messages, now));
    if (digest.ids.length) {
      // Mark in chunks of 90 ids (D1: max 100 bound parameters per statement).
      for (let i = 0; i < digest.ids.length; i += 90) {
        const chunk = digest.ids.slice(i, i + 90);
        stmts.push(
          env.DB.prepare(`UPDATE incidents SET digested_at = ? WHERE id IN (${chunk.map(() => '?').join(',')})`).bind(now, ...chunk),
        );
      }
    }
    stmts.push(settingStatement(env, 'last_digest', local.date));
    sent.push('digest');
  }

  const week = isoWeekKey(local);
  if (local.weekday === 1 && get('last_weekly') !== week) {
    stmts.push(...queueTextStatements(env, await weeklyMessages(env, now), now));
    stmts.push(settingStatement(env, 'last_weekly', week));
    sent.push('weekly');
  }
  if (stmts.length) await env.DB.batch(stmts);
  return sent;
}

function settingStatement(env: Env, key: string, value: string): D1PreparedStatement {
  return env.DB.prepare('INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2').bind(key, value);
}
