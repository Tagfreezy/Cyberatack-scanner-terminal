import { AiQuotaError, classify, embed, embeddingText, type Classification } from './ai';
import { cosine, DEDUPE_WINDOW_MS, extractCve, findMatch, victimKey, type Candidate } from './dedupe';
import { log, logError } from './log';
import { scoreItem } from './scoring';
import type { AttackType, Env, Item, ItemMeta } from './types';

// Stage 2 of the pipeline: take a few 'pending' items, classify (AI, keyword fallback),
// dedupe into incidents, queue alerts/edits.
//
// Subrequest budget (free plan: 50 per invocation, shared by D1, fetch, AI, Vectorize):
//   fixed ≈ 5 (settings, pending, candidates, embed, upsert) + per item ≈ 4
//   (classify + 1 retry, Vectorize query, D1 batch). AI_ITEMS_PER_RUN=4 → ~21, leaving
//   room for 2 source fetches (~8) and the Telegram outbox (~9). Backlog drains next tick.

const RECENT_VECTOR_MS = 30 * 60_000;

/** D1 returns a BLOB as an array of byte values; rebuild the Float32 vector from it. */
export function blobToVector(blob: number[] | ArrayBuffer): Float32Array {
  const bytes = blob instanceof ArrayBuffer ? new Uint8Array(blob) : Uint8Array.from(blob);
  return new Float32Array(bytes.buffer, bytes.byteOffset, Math.floor(bytes.byteLength / 4));
}

/** Types where "victim" is a real victim. For zero-days/supply-chain the AI puts the vendor
 * there ("Microsoft"), which must not merge unrelated stories, so no victim matching. */
const VICTIM_TYPES: AttackType[] = ['ransomware', 'breach', 'ddos', 'wiper', 'other'];

interface Decision {
  isIncident: boolean;
  attackType: AttackType;
  severity: number;
  victim: string | null;
  sector: string | null;
  country: string | null;
  summary: string | null;
  classifiedBy: 'ai' | 'keywords';
}

interface CandidateRow extends Candidate {
  attack_type: string | null;
  severity: number;
  source_count: number;
  sources: string | null;
  alert_state: string;
  telegram_message_id: number | null;
  classified_by: string | null;
  victim: string | null;
  sector: string | null;
  country: string | null;
}

interface PendingRow {
  id: string;
  source: string;
  title: string;
  url: string | null;
  published_at: number | null;
  summary: string | null;
  type_hint: Item['typeHint'];
  meta: string | null;
}

/** Combine AI output (if any) with what the source already told us. Pure → unit-tested. */
export function decide(item: Item, ai: Classification | null): Decision {
  const kw = scoreItem(item);
  if (!ai) {
    return {
      isIncident: kw.isIncident,
      attackType: kw.attackType,
      severity: kw.severity,
      victim: item.meta.victim ?? null,
      sector: item.meta.sector ?? null,
      country: item.meta.country ?? null,
      summary: item.summary ? item.summary.slice(0, 300) : null,
      classifiedBy: 'keywords',
    };
  }
  if (item.typeHint === 'leak') {
    // A leak-site post is always a ransomware claim; source data beats AI guesses for
    // victim/country. Severity stays on the strict keyword rule (public-impact victims → 4):
    // in an eval on 28 real posts the AI rated a title-insurance firm 4, and ~65 posts/day
    // would mean several false "high" alerts daily. The AI adds sector + summary only.
    return {
      isIncident: true,
      attackType: 'ransomware',
      severity: kw.severity,
      victim: item.meta.victim ?? ai.victim,
      sector: item.meta.sector ?? ai.sector,
      country: item.meta.country ?? ai.country,
      summary: ai.summary || null,
      classifiedBy: 'ai',
    };
  }
  return {
    isIncident: ai.is_incident,
    attackType: ai.attack_type,
    severity: ai.is_incident ? ai.severity : 1,
    victim: ai.victim,
    sector: ai.sector,
    country: ai.country,
    summary: ai.summary || null,
    classifiedBy: 'ai',
  };
}

function rowToItem(r: PendingRow): Item {
  let meta: ItemMeta = {};
  try {
    meta = r.meta ? (JSON.parse(r.meta) as ItemMeta) : {};
  } catch {
    /* ignore */
  }
  return {
    id: r.id,
    source: r.source,
    title: r.title,
    url: r.url,
    publishedAt: r.published_at,
    summary: r.summary ?? '',
    typeHint: r.type_hint,
    meta,
  };
}

function parseSources(s: string | null): string[] {
  try {
    return s ? (JSON.parse(s) as string[]) : [];
  } catch {
    return [];
  }
}

export interface ProcessReport {
  processed: number;
  incidents: number;
  merged: number;
  rejected: number;
  alerts: number;
  edits: number;
  aiUsed: number;
  fallback: number;
  aiPaused: boolean;
}

/**
 * @param deadline no NEW item is started after this time (the 8B model takes ~5 s per
 * item); unstarted items stay 'pending' and are picked up next tick.
 */
export async function processPending(env: Env, now = Date.now(), deadline = now + 30_000): Promise<ProcessReport> {
  const report: ProcessReport = { processed: 0, incidents: 0, merged: 0, rejected: 0, alerts: 0, edits: 0, aiUsed: 0, fallback: 0, aiPaused: false };
  const limit = Number(env.AI_ITEMS_PER_RUN) || 4;
  const simThreshold = Number(env.SIM_THRESHOLD) || 0.7;

  const { results: pending } = await env.DB.prepare(
    `SELECT id, source, title, url, published_at, summary, type_hint, meta FROM items
     WHERE status = 'pending' ORDER BY created_at, id LIMIT ?`,
  )
    .bind(limit)
    .all<PendingRow>();
  if (!pending.length) return report;

  const settings = await env.DB.prepare("SELECT key, value FROM settings WHERE key IN ('threshold', 'ai_paused_until')").all<{
    key: string;
    value: string;
  }>();
  const setting = (k: string) => settings.results.find((r) => r.key === k)?.value;
  const threshold = Number(setting('threshold') ?? env.ALERT_THRESHOLD) || 4;
  let aiPausedUntil = Number(setting('ai_paused_until') ?? 0);

  // ---- 1. classify ---------------------------------------------------------------------
  const items: Item[] = [];
  const decisions: Decision[] = [];
  for (const row of pending) {
    if (Date.now() > deadline) break;
    const item = rowToItem(row);
    items.push(item);
    let ai: Classification | null = null;
    // KEV entries are already structured; leak posts with no description give the AI nothing.
    const wantsAi = item.typeHint === 'news' || (item.typeHint === 'leak' && item.summary.length > 20);
    if (wantsAi && aiPausedUntil <= now) {
      try {
        ai = await classify(env, item);
        if (ai) report.aiUsed++;
        else logError('ai.fallback', 'invalid output twice', { item: item.id });
      } catch (err) {
        if (err instanceof AiQuotaError) {
          aiPausedUntil = err.until;
          await env.DB.prepare(
            "INSERT INTO settings (key, value) VALUES ('ai_paused_until', ?1) ON CONFLICT(key) DO UPDATE SET value = ?1",
          )
            .bind(String(err.until))
            .run();
          logError('ai.paused', err, { until: new Date(err.until).toISOString() });
        } else {
          logError('ai.classify', err, { item: item.id });
        }
      }
    }
    if (wantsAi && !ai) report.fallback++;
    decisions.push(decide(item, ai));
  }
  report.aiPaused = aiPausedUntil > now;

  // ---- 2. embed all incident candidates in ONE call --------------------------------------
  const incidentIdx = decisions.map((d, i) => (d.isIncident ? i : -1)).filter((i) => i >= 0);
  let vectors: (number[] | null)[] = items.map(() => null);
  if (incidentIdx.length && !report.aiPaused) {
    try {
      const vecs = await embed(
        env,
        incidentIdx.map((i) => embeddingText(items[i]!.title, items[i]!.summary)),
      );
      vectors = items.map((_, i) => {
        const k = incidentIdx.indexOf(i);
        return k >= 0 ? (vecs[k] ?? null) : null;
      });
    } catch (err) {
      // Without vectors we still dedupe by CVE + victim name.
      logError('ai.embed', err);
    }
  }

  // ---- 3. dedupe + store, one D1 batch per item --------------------------------------------
  const { results: candidates } = await env.DB.prepare(
    `SELECT id, victim_key, cve, first_seen, attack_type, severity, source_count, sources, alert_state,
            telegram_message_id, classified_by, victim, sector, country
     FROM incidents WHERE first_seen > ?`,
  )
    .bind(now - DEDUPE_WINDOW_MS)
    .all<CandidateRow>();
  const newVectors: { id: number; values: number[] }[] = [];

  // Vectorize applies writes asynchronously, and lag of ~10 min was observed. So vectors
  // of incidents from the last 30 min are also kept in D1 and compared here, in-memory.
  // Only a handful of rows, so the BLOB→array conversion stays cheap.
  const recentVectors: { id: number; values: Float32Array }[] = [];
  if (incidentIdx.length && vectors.some(Boolean)) {
    const { results: recent } = await env.DB.prepare(
      'SELECT id, embedding FROM incidents WHERE embedding IS NOT NULL AND first_seen > ? LIMIT 50',
    )
      .bind(now - RECENT_VECTOR_MS)
      .all<{ id: number; embedding: number[] }>();
    for (const r of recent) recentVectors.push({ id: r.id, values: blobToVector(r.embedding) });
  }

  for (const [i, item] of items.entries()) {
    const d = decisions[i]!;
    report.processed++;

    if (!d.isIncident) {
      report.rejected++;
      await env.DB.prepare("UPDATE items SET status = 'rejected', severity = ?, attack_type = ? WHERE id = ?")
        .bind(d.severity, d.attackType, item.id)
        .run();
      continue;
    }

    const isVictimType = VICTIM_TYPES.includes(d.attackType);
    const vKey = isVictimType ? victimKey(d.victim) : null;
    const cve = item.meta.cve ?? extractCve(`${item.title} ${item.summary}`);
    const vec = vectors[i];

    // Similar vectors: Vectorize (incidents from earlier runs) + vectors created in this run
    // (Vectorize is eventually consistent, fresh upserts aren't queryable for a few seconds).
    const hits: { id: number; score: number }[] = [];
    if (vec) {
      try {
        const res = await env.VECTORS.query(vec, {
          topK: 5,
          filter: { first_seen: { $gte: now - DEDUPE_WINDOW_MS } },
        });
        for (const m of res.matches) hits.push({ id: Number(m.id), score: m.score });
      } catch (err) {
        logError('vectorize.query', err);
      }
      for (const nv of newVectors) hits.push({ id: nv.id, score: cosine(vec, nv.values) });
      for (const rv of recentVectors) {
        if (!hits.some((h) => h.id === rv.id)) hits.push({ id: rv.id, score: cosine(vec, rv.values) });
      }
    }

    // Victim matching only between "victim-type" incidents (see VICTIM_TYPES).
    const victimCandidates = candidates.map((c) =>
      c.attack_type && !VICTIM_TYPES.includes(c.attack_type as AttackType) ? { ...c, victim_key: null } : c,
    );
    const match = findMatch({ victimKey: vKey, cve }, victimCandidates, hits, simThreshold, now);
    // Top scores, for tuning SIM_THRESHOLD from real traffic (`npm run tail`).
    log('dedupe.check', {
      item: item.id,
      vkey: vKey,
      cve,
      vec: vec ? 'yes' : 'no',
      top: [...hits].sort((a, b) => b.score - a.score).slice(0, 3).map((h) => `${h.id}:${h.score.toFixed(3)}`),
      match: match ? `${match.id}/${match.reason}` : null,
    });

    if (match) {
      const inc = candidates.find((c) => c.id === match.id)!;
      const sources = parseSources(inc.sources);
      const sourceAdded = !sources.includes(item.source);
      if (sourceAdded) sources.push(item.source);
      const severity = Math.max(inc.severity, d.severity);
      // An AI classification upgrades a keyword-only incident's details.
      const upgrade = d.classifiedBy === 'ai' && inc.classified_by !== 'ai';

      let alertState = inc.alert_state;
      let outbox: 'alert' | 'edit' | null = null;
      if (inc.alert_state === 'sent' && inc.telegram_message_id && (sourceAdded || severity !== inc.severity || upgrade)) {
        outbox = 'edit';
      } else if (['digest', 'none', 'baseline'].includes(inc.alert_state) && severity >= threshold && sourceAdded) {
        outbox = 'alert';
        alertState = 'queued';
      }

      // ?6 = "upgrade" flag, reused by three CASEs.
      const stmts: D1PreparedStatement[] = [];
      stmts.push(env.DB.prepare(
        `UPDATE incidents SET source_count = ?1, sources = ?2, severity = ?3, last_seen = ?4, alert_state = ?5,
           summary = CASE WHEN ?6 THEN ?7 ELSE summary END,
           attack_type = CASE WHEN ?6 THEN ?8 ELSE attack_type END,
           classified_by = CASE WHEN ?6 THEN 'ai' ELSE classified_by END,
           victim = COALESCE(victim, ?9), sector = COALESCE(sector, ?10), country = COALESCE(country, ?11),
           victim_key = COALESCE(victim_key, ?12), cve = COALESCE(cve, ?13)
         WHERE id = ?14`,
      ).bind(
        sources.length,
        JSON.stringify(sources),
        severity,
        now,
        alertState,
        upgrade ? 1 : 0,
        d.summary,
        d.attackType,
        d.victim,
        d.sector,
        d.country,
        vKey,
        cve,
        inc.id,
      ));
      stmts.push(
        env.DB.prepare(
          "UPDATE items SET status = 'classified', is_incident = 1, severity = ?, attack_type = ?, incident_id = ? WHERE id = ?",
        ).bind(d.severity, d.attackType, inc.id, item.id),
      );
      if (outbox) {
        // At most one pending message per incident: a queued alert/edit is rendered from the
        // incident row at send time, so it already shows the newest source count.
        stmts.push(
          env.DB.prepare(
            `INSERT INTO outbox (kind, incident_id, payload, next_attempt_at, created_at)
             SELECT ?1, ?2, '{}', ?3, ?3
             WHERE NOT EXISTS (SELECT 1 FROM outbox WHERE incident_id = ?2 AND sent_at IS NULL AND attempts < 5)`,
          ).bind(outbox, inc.id, now),
        );
      }
      await env.DB.batch(stmts);

      Object.assign(inc, { sources: JSON.stringify(sources), source_count: sources.length, severity, alert_state: alertState });
      if (upgrade) inc.classified_by = 'ai';
      report.merged++;
      if (outbox === 'alert') report.alerts++;
      if (outbox === 'edit') report.edits++;
      log('dedupe.merge', { item: item.id, incident: inc.id, reason: match.reason, score: match.score, sources: sources.length });
      continue;
    }

    // ---- new incident ----
    const alertState = d.severity >= threshold ? 'queued' : 'digest';
    const res = await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO incidents (title, summary, url, attack_type, victim, group_name, vendor, sector, country, severity,
           source_count, sources, classified_by, first_seen, last_seen, alert_state, cve, victim_key, vectorized, embedding)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, 0, ?) RETURNING id`,
      ).bind(
        item.title,
        d.summary,
        item.url,
        d.attackType,
        d.victim,
        item.meta.group ?? null,
        item.meta.vendor ?? null,
        d.sector,
        d.country,
        d.severity,
        JSON.stringify([item.source]),
        d.classifiedBy,
        now,
        now,
        alertState,
        cve,
        vKey,
        vec ? new Float32Array(vec).buffer : null,
      ),
      env.DB.prepare(
        `UPDATE items SET status = 'classified', is_incident = 1, severity = ?, attack_type = ?,
           incident_id = (SELECT MAX(id) FROM incidents) WHERE id = ?`,
      ).bind(d.severity, d.attackType, item.id),
      ...(alertState === 'queued'
        ? [
            env.DB.prepare(
              `INSERT INTO outbox (kind, incident_id, payload, next_attempt_at, created_at)
               VALUES ('alert', (SELECT MAX(id) FROM incidents), '{}', ?, ?)`,
            ).bind(now, now),
          ]
        : []),
    ]);
    const id = (res[0]!.results[0] as { id: number }).id;
    candidates.push({
      id,
      victim_key: vKey,
      cve,
      first_seen: now,
      attack_type: d.attackType,
      severity: d.severity,
      source_count: 1,
      sources: JSON.stringify([item.source]),
      alert_state: alertState,
      telegram_message_id: null,
      classified_by: d.classifiedBy,
      victim: d.victim,
      sector: d.sector,
      country: d.country,
    });
    if (vec) newVectors.push({ id, values: vec });
    report.incidents++;
    if (alertState === 'queued') report.alerts++;
  }

  // ---- 4. one Vectorize upsert for all new incidents ------------------------------------------
  if (newVectors.length) {
    try {
      await env.VECTORS.upsert(newVectors.map((v) => ({ id: String(v.id), values: v.values, metadata: { first_seen: now } })));
      await env.DB.prepare(
        `UPDATE incidents SET vectorized = 1 WHERE id IN (${newVectors.map(() => '?').join(',')})`,
      )
        .bind(...newVectors.map((v) => v.id))
        .run();
    } catch (err) {
      // vectorized stays 0 → backfillVectors() retries later.
      logError('vectorize.upsert', err);
    }
  }

  log('process', { ok: true, ...report });
  return report;
}

/**
 * Self-healing: give recent incidents that have no vector yet (phase-1/baseline incidents,
 * failed upserts) an embedding + victim key, so they take part in dedupe. 4 subrequests.
 */
export async function backfillVectors(env: Env, now = Date.now(), max = 25): Promise<number> {
  const paused = await env.DB.prepare("SELECT value FROM settings WHERE key = 'ai_paused_until'").first<{ value: string }>();
  if (Number(paused?.value ?? 0) > now) return 0;
  const { results } = await env.DB.prepare(
    // Raw source summary of the incident's first item (same embedding recipe as new items).
    `SELECT id, title, victim, attack_type, first_seen,
            (SELECT it.summary FROM items it WHERE it.incident_id = incidents.id ORDER BY it.created_at LIMIT 1) AS summary
     FROM incidents WHERE vectorized = 0 AND first_seen > ? ORDER BY first_seen DESC LIMIT ?`,
  )
    .bind(now - DEDUPE_WINDOW_MS, max)
    .all<{ id: number; title: string; summary: string | null; victim: string | null; attack_type: string | null; first_seen: number }>();
  if (!results.length) return 0;
  try {
    const vecs = await embed(env, results.map((r) => embeddingText(r.title, r.summary)));
    await env.VECTORS.upsert(results.map((r, i) => ({ id: String(r.id), values: vecs[i]!, metadata: { first_seen: r.first_seen } })));
    await env.DB.batch(
      results.map((r) =>
        env.DB.prepare('UPDATE incidents SET vectorized = 1, victim_key = COALESCE(victim_key, ?) WHERE id = ?').bind(
          r.attack_type && VICTIM_TYPES.includes(r.attack_type as AttackType) ? victimKey(r.victim) : null,
          r.id,
        ),
      ),
    );
    log('vectors.backfill', { ok: true, count: results.length });
    return results.length;
  } catch (err) {
    logError('vectors.backfill', err);
    return 0;
  }
}

/** Daily: remove vectors older than 7 days (dedupe only looks back 72h; keeps Vectorize small). */
export async function expireVectors(env: Env, now = Date.now()): Promise<void> {
  const { results } = await env.DB.prepare('SELECT id FROM incidents WHERE vectorized = 1 AND first_seen < ? LIMIT 1000')
    .bind(now - 7 * 86_400_000)
    .all<{ id: number }>();
  if (!results.length) return;
  await env.VECTORS.deleteByIds(results.map((r) => String(r.id)));
  await env.DB.prepare(`UPDATE incidents SET vectorized = 2 WHERE vectorized = 1 AND first_seen < ?`).bind(now - 7 * 86_400_000).run();
  log('vectors.expire', { ok: true, count: results.length });
}

/** Daily: drop the short-lived D1 copies of vectors (only needed for the first 30 min). */
export async function clearRecentVectors(env: Env, now = Date.now()): Promise<void> {
  await env.DB.prepare('UPDATE incidents SET embedding = NULL WHERE embedding IS NOT NULL AND first_seen < ?')
    .bind(now - 86_400_000)
    .run();
}
