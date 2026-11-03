import { AiQuotaError, explainIncident } from './ai';
import { logError } from './log';
import { localMidnight } from './time';
import type { Env } from './types';
import { staleAfterMs } from './telegram/webhook';

// JSON API for the terminal dashboard (bearer token checked in index.ts).
//
// D1 free plan = 5M rows read/day. A dashboard polling every 30 s that recomputed stats per
// request would read ~17M rows/day. So stats are precomputed into one settings row by the
// cron (only when incidents changed, at most every 5 min) and /api/stats reads that row; the
// feed is incremental (?since=cursor uses the last_seen index). A poll costs ~10 row reads.

const FEED_COLS = `id, title, summary, url, attack_type, severity, victim, group_name, vendor, sector, country,
  source_count, sources, first_seen, last_seen, alert_state, classified_by, details`;

interface FeedRow {
  sources: string | null;
  last_seen: number;
  [k: string]: unknown;
}

const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });

function parseSources(s: string | null): string[] {
  try {
    return s ? (JSON.parse(s) as string[]) : [];
  } catch {
    return [];
  }
}

export async function handleApi(req: Request, env: Env, url: URL): Promise<Response | null> {
  const path = url.pathname;

  if (path === '/api/feed' && req.method === 'GET') {
    const since = Number(url.searchParams.get('since') ?? 0) || 0;
    const limit = Math.max(1, Math.min(300, Number(url.searchParams.get('limit')) || 150));
    // since=0: newest incidents. since>0: everything created OR updated (merged) after the cursor.
    const stmt = since
      ? env.DB.prepare(`SELECT ${FEED_COLS} FROM incidents WHERE last_seen > ? ORDER BY last_seen DESC LIMIT ?`).bind(since, limit)
      : env.DB.prepare(`SELECT ${FEED_COLS} FROM incidents ORDER BY first_seen DESC, id DESC LIMIT ?`).bind(limit);
    const { results } = await stmt.all<FeedRow>();
    const incidents = results.map((r) => ({ ...r, sources: parseSources(r.sources) }));
    const cursor = results.reduce((m, r) => Math.max(m, Number(r.last_seen) || 0), since);
    return json({ generated_at: Date.now(), cursor, incidents });
  }

  if (path === '/api/stats' && req.method === 'GET') {
    const [snap, health] = await Promise.all([
      env.DB.prepare("SELECT value FROM settings WHERE key = 'stats_snapshot'").first<{ value: string }>(),
      sourceHealth(env),
    ]);
    const stats = snap ? (JSON.parse(snap.value) as Record<string, unknown>) : await computeStats(env);
    return json({ ...stats, ...health, served_at: Date.now() });
  }

  if (path === '/api/sensors' && req.method === 'GET') {
    const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'sensors_snapshot'").first<{ value: string }>();
    // Filled by the SANS ISC source in phase 5.
    return json(row ? JSON.parse(row.value) : { available: false, note: 'SANS ISC sensor data arrives in phase 5' });
  }

  // On-demand AI explanation for the dashboard's detail view (same cache as the Telegram button).
  const explain = path.match(/^\/api\/incident\/(\d+)\/explain$/);
  if (explain && req.method === 'POST') {
    const id = Number(explain[1]);
    const inc = await env.DB.prepare(
      'SELECT id, title, summary, attack_type, victim, sector, country, details FROM incidents WHERE id = ?',
    )
      .bind(id)
      .first<{ id: number; title: string; summary: string | null; attack_type: string | null; victim: string | null; sector: string | null; country: string | null; details: string | null }>();
    if (!inc) return json({ error: 'not found' }, 404);
    if (inc.details) return json({ details: inc.details, cached: true });
    const { results: reports } = await env.DB.prepare('SELECT source, title, summary FROM items WHERE incident_id = ? LIMIT 4')
      .bind(id)
      .all<{ source: string; title: string; summary: string | null }>();
    try {
      const details = await explainIncident(env, inc, reports);
      if (details) await env.DB.prepare('UPDATE incidents SET details = ? WHERE id = ?').bind(details, id).run();
      return json({ details, cached: false });
    } catch (err) {
      if (!(err instanceof AiQuotaError)) logError('api.explain', err);
      return json({ error: 'AI unavailable right now' }, 503);
    }
  }

  return null;
}

/** Live (not snapshotted): per-source health + queue sizes. ~10 rows. */
async function sourceHealth(env: Env) {
  const [src, misc] = await env.DB.batch([
    env.DB.prepare('SELECT source, last_ok, last_error, last_error_at FROM source_state ORDER BY source'),
    env.DB.prepare(
      `SELECT (SELECT COUNT(*) FROM items WHERE status = 'pending') AS queue,
              (SELECT value FROM settings WHERE key = 'ai_paused_until') AS ai_paused_until`,
    ),
  ]);
  const now = Date.now();
  const sources = (src!.results as { source: string; last_ok: number | null; last_error: string | null; last_error_at: number | null }[]).map(
    (r) => {
      const failing = (r.last_error_at ?? 0) > (r.last_ok ?? 0);
      const stale = now - (r.last_ok ?? 0) > staleAfterMs(r.source);
      return { ...r, ok: !failing && !stale };
    },
  );
  const m = misc!.results[0] as { queue: number; ai_paused_until: string | null } | undefined;
  return { sources, queue: m?.queue ?? 0, ai_paused: Number(m?.ai_paused_until ?? 0) > now };
}

const DAY = 86_400_000;

/** Full stats (SQL aggregation). Called by the cron when incidents changed, stored as one row. */
export async function computeStats(env: Env, now = Date.now()): Promise<Record<string, unknown>> {
  const today = localMidnight(now, env.TIMEZONE);
  const w = now - 7 * DAY;
  const pw = now - 14 * DAY;
  const res = await env.DB.batch([
    env.DB.prepare(
      `SELECT COALESCE(SUM(first_seen >= ?1), 0) AS today, COALESCE(SUM(first_seen >= ?2), 0) AS week,
              COALESCE(SUM(first_seen < ?2), 0) AS prev_week,
              COALESCE(SUM(first_seen >= ?2 AND severity >= 4), 0) AS week_high,
              COALESCE(SUM(first_seen >= ?2 AND source_count > 1), 0) AS week_multi,
              MAX(last_seen) AS watermark
       FROM incidents WHERE first_seen >= ?3`,
    ).bind(today, w, pw),
    env.DB.prepare(`SELECT COALESCE(attack_type, 'other') AS key, COUNT(*) AS n FROM incidents WHERE first_seen >= ? GROUP BY 1 ORDER BY n DESC`).bind(w),
    env.DB.prepare(`SELECT severity AS key, COUNT(*) AS n FROM incidents WHERE first_seen >= ? GROUP BY 1 ORDER BY 1 DESC`).bind(w),
    env.DB.prepare(
      `SELECT sector AS key, COUNT(*) AS n FROM incidents WHERE first_seen >= ? AND sector IS NOT NULL AND sector != 'Other'
       GROUP BY 1 ORDER BY n DESC LIMIT 8`,
    ).bind(w),
    // All countries (the world map needs every one, not a top-N).
    env.DB.prepare(`SELECT country AS key, COUNT(*) AS n FROM incidents WHERE first_seen >= ? AND country IS NOT NULL GROUP BY 1 ORDER BY n DESC`).bind(w),
    env.DB.prepare(
      `SELECT MAX(group_name) AS key, COUNT(*) AS n FROM incidents WHERE first_seen >= ? AND group_name IS NOT NULL
       GROUP BY lower(group_name) ORDER BY n DESC LIMIT 10`,
    ).bind(w),
    // Activity per hour over the last 24 h (dashboard sparkline).
    env.DB.prepare(
      `SELECT CAST((first_seen - ?1) / 3600000 AS INTEGER) AS h, COUNT(*) AS n FROM incidents WHERE first_seen >= ?1 GROUP BY 1`,
    ).bind(now - DAY),
  ]);
  const r0 = (res[0]!.results[0] ?? {}) as Record<string, number>;
  const hourly = new Array(24).fill(0) as number[];
  for (const r of res[6]!.results as { h: number; n: number }[]) if (r.h >= 0 && r.h < 24) hourly[r.h] = r.n;
  return {
    computed_at: now,
    watermark: r0.watermark ?? 0,
    today: r0.today ?? 0,
    week: r0.week ?? 0,
    prev_week: r0.prev_week ?? 0,
    week_high: r0.week_high ?? 0,
    week_multi: r0.week_multi ?? 0,
    by_type: res[1]!.results,
    by_severity: res[2]!.results,
    by_sector: res[3]!.results,
    by_country: res[4]!.results,
    groups: res[5]!.results,
    hourly,
  };
}

/**
 * Cron step: refresh the stats snapshot if incidents changed since it was computed (one
 * indexed MAX() read), or if it's older than 15 min ("today" rolls over at midnight).
 */
export async function refreshStatsSnapshot(env: Env, now = Date.now()): Promise<boolean> {
  const [snap, wm] = await env.DB.batch([
    env.DB.prepare("SELECT value FROM settings WHERE key = 'stats_snapshot'"),
    env.DB.prepare('SELECT MAX(last_seen) AS m FROM incidents'),
  ]);
  const prev = snap!.results[0] ? (JSON.parse((snap!.results[0] as { value: string }).value) as { watermark: number; computed_at: number }) : null;
  const watermark = Number((wm!.results[0] as { m: number | null } | undefined)?.m ?? 0);
  if (prev && prev.watermark >= watermark && now - prev.computed_at < 15 * 60_000) return false;
  const stats = await computeStats(env, now);
  stats.watermark = Math.max(Number(stats.watermark) || 0, watermark);
  await env.DB.prepare(
    "INSERT INTO settings (key, value) VALUES ('stats_snapshot', ?1) ON CONFLICT(key) DO UPDATE SET value = ?1",
  )
    .bind(JSON.stringify(stats))
    .run();
  return true;
}
