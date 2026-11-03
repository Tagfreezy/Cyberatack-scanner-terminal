import { victimKey } from './dedupe';
import type { Env, Item, Score, SourceState } from './types';

export async function getSourceState(db: D1Database, source: string): Promise<SourceState | null> {
  return db
    .prepare('SELECT source, etag, last_modified, initialized, extra FROM source_state WHERE source = ?')
    .bind(source)
    .first<SourceState>();
}

/** Statement marking a source run as successful (run alone, or inside a batch). */
export function sourceOkStatement(
  db: D1Database,
  source: string,
  v: { etag?: string | null; lastModified?: string | null; extra?: unknown; fetched: number; fresh: number },
  now: number,
): D1PreparedStatement {
  // COALESCE keeps the old validators when the response (e.g. a 304) didn't send new ones.
  return db
    .prepare(
      `INSERT INTO source_state (source, etag, last_modified, initialized, last_run, last_ok, last_fetched, last_new, extra)
       VALUES (?1, ?2, ?3, 1, ?4, ?4, ?5, ?6, ?7)
       ON CONFLICT(source) DO UPDATE SET
         etag = COALESCE(?2, etag), last_modified = COALESCE(?3, last_modified), initialized = 1,
         last_run = ?4, last_ok = ?4, last_fetched = ?5, last_new = ?6, extra = COALESCE(?7, extra)`,
    )
    .bind(
      source,
      v.etag ?? null,
      v.lastModified ?? null,
      now,
      v.fetched,
      v.fresh,
      v.extra === undefined ? null : JSON.stringify(v.extra),
    );
}

export async function markSourceError(db: D1Database, source: string, err: string, now: number): Promise<void> {
  await db
    .prepare(
      `INSERT INTO source_state (source, last_run, last_error, last_error_at) VALUES (?1, ?2, ?3, ?2)
       ON CONFLICT(source) DO UPDATE SET last_run = ?2, last_error = ?3, last_error_at = ?2`,
    )
    .bind(source, now, err.slice(0, 500))
    .run();
}

/** Ids from `ids` that already exist in items. One query per 90 ids (D1 caps bound params at 100). */
export async function seenIds(db: D1Database, ids: string[]): Promise<Set<string>> {
  const seen = new Set<string>();
  for (let i = 0; i < ids.length; i += 90) {
    const chunk = ids.slice(i, i + 90);
    const q = `SELECT id FROM items WHERE id IN (${chunk.map(() => '?').join(',')})`;
    const { results } = await db
      .prepare(q)
      .bind(...chunk)
      .all<{ id: string }>();
    for (const r of results) seen.add(r.id);
  }
  return seen;
}

export async function getSetting(db: D1Database, key: string): Promise<string | null> {
  const r = await db.prepare('SELECT value FROM settings WHERE key = ?').bind(key).first<{ value: string }>();
  return r?.value ?? null;
}

export async function setSetting(db: D1Database, key: string, value: string): Promise<void> {
  await db
    .prepare('INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2')
    .bind(key, value)
    .run();
}

export async function getThreshold(env: Env): Promise<number> {
  const v = Number((await getSetting(env.DB, 'threshold')) ?? env.ALERT_THRESHOLD ?? 4);
  return v >= 1 && v <= 5 ? v : 4;
}

// D1 batches run atomically and in order, so right after an incident INSERT the max id is
// that incident: items/outbox rows can reference it without an extra round-trip.
const LAST_INCIDENT = `(SELECT MAX(id) FROM incidents)`;

export type AlertState = 'queued' | 'digest' | 'baseline';

/** Statements that insert an item. With `score.isIncident`, also an incident (+ outbox alert when queued). */
export function itemStatements(
  db: D1Database,
  item: Item,
  score: Score | null,
  status: 'baseline' | 'filtered' | 'pending',
  alertState: AlertState,
  now: number,
): D1PreparedStatement[] {
  const stmts: D1PreparedStatement[] = [];
  const withIncident = score?.isIncident === true;

  if (withIncident) {
    stmts.push(
      db
        .prepare(
          `INSERT INTO incidents (title, summary, url, attack_type, victim, group_name, vendor, sector, country,
             severity, source_count, sources, classified_by, first_seen, last_seen, alert_state, cve, victim_key)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 'keywords', ?, ?, ?, ?, ?)`,
        )
        .bind(
          item.title,
          item.summary || null,
          item.url,
          score!.attackType,
          item.meta.victim ?? null,
          item.meta.group ?? null,
          item.meta.vendor ?? null,
          item.meta.sector ?? null,
          item.meta.country ?? null,
          score!.severity,
          JSON.stringify([item.source]),
          now,
          now,
          alertState,
          item.meta.cve ?? null,
          // Only leak posts carry a real victim name from the source itself.
          item.typeHint === 'leak' ? victimKey(item.meta.victim) : null,
        ),
    );
  }

  stmts.push(
    db
      .prepare(
        `INSERT OR IGNORE INTO items (id, source, title, url, published_at, summary, type_hint, status,
           is_incident, severity, attack_type, incident_id, meta, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ${withIncident ? LAST_INCIDENT : 'NULL'}, ?, ?)`,
      )
      .bind(
        item.id,
        item.source,
        item.title,
        item.url,
        item.publishedAt,
        item.summary || null,
        item.typeHint,
        status,
        withIncident ? 1 : 0,
        score?.severity ?? 0,
        score?.attackType ?? null,
        JSON.stringify(item.meta),
        now,
      ),
  );

  if (withIncident && alertState === 'queued') {
    stmts.push(
      db
        .prepare(
          `INSERT INTO outbox (kind, incident_id, payload, next_attempt_at, created_at)
           VALUES ('alert', ${LAST_INCIDENT}, '{}', ?, ?)`,
        )
        .bind(now, now),
    );
  }
  return stmts;
}
