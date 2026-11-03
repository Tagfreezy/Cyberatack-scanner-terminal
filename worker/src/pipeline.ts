import { getSourceState, getThreshold, itemStatements, markSourceError, markSourceOk, seenIds } from './db';
import { log, logError } from './log';
import { scoreItem } from './scoring';
import type { Source } from './sources/types';
import type { Env } from './types';

export interface SourceRunReport {
  source: string;
  ok: boolean;
  notModified?: boolean;
  baseline?: boolean;
  fetched?: number;
  fresh?: number;
  incidents?: number;
  alerts?: number;
  error?: string;
  ms: number;
}

/**
 * Fetch → normalize → skip seen → keyword score → store → queue alerts, for ONE source.
 * Never throws: a broken source is logged + recorded in source_state and the others go on.
 */
export async function runSource(env: Env, source: Source, now = Date.now()): Promise<SourceRunReport> {
  const t0 = Date.now();
  try {
    const state = await getSourceState(env.DB, source.name);
    const result = await source.run(env, state);

    if (result.items === null) {
      await markSourceOk(env.DB, source.name, { ...result, fetched: 0, fresh: 0 }, now);
      const r = { source: source.name, ok: true, notModified: true, ms: Date.now() - t0 };
      log('source.run', r);
      return r;
    }

    const items = result.items;
    const seen = await seenIds(env.DB, items.map((i) => i.id));
    const fresh = items.filter((i) => !seen.has(i.id));

    // First successful run for a source: store everything silently, so a fresh deploy
    // doesn't flood the chat with ~100 "new" items that are actually days old.
    const baseline = !state || state.initialized === 0;
    const threshold = await getThreshold(env);

    const stmts: D1PreparedStatement[] = [];
    let incidents = 0;
    let alerts = 0;
    for (const item of fresh) {
      const score = scoreItem(item);
      const status = baseline ? 'baseline' : score.isIncident ? 'scored' : 'filtered';
      const alertState = baseline ? 'baseline' : score.severity >= threshold ? 'queued' : 'digest';
      if (score.isIncident) incidents++;
      if (score.isIncident && alertState === 'queued') alerts++;
      stmts.push(...itemStatements(env.DB, item, score, status, alertState, now));
    }
    if (stmts.length) await env.DB.batch(stmts);

    // Validators are saved only now, after the items are stored: if anything above failed,
    // the next run re-fetches instead of getting a 304 and losing those items for good.
    await markSourceOk(env.DB, source.name, { ...result, fetched: items.length, fresh: fresh.length }, now);

    const r = {
      source: source.name,
      ok: true,
      baseline,
      fetched: items.length,
      fresh: fresh.length,
      incidents,
      alerts,
      ms: Date.now() - t0,
    };
    log('source.run', r);
    return r;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logError('source.run', err, { source: source.name });
    await markSourceError(env.DB, source.name, message, now).catch(() => {});
    return { source: source.name, ok: false, error: message, ms: Date.now() - t0 };
  }
}
