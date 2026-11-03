import { getSourceState, itemStatements, markSourceError, sourceOkStatement, seenIds } from './db';
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
  pending?: number;
  filtered?: number;
  error?: string;
  ms: number;
}

/**
 * Stage 1, for ONE source: fetch → normalize → skip seen → keyword pre-filter → store.
 * New items are stored as 'pending'; process.ts classifies them (AI) a few per tick.
 * Never throws: a broken source is logged + recorded in source_state and the others go on.
 * D1 cost: state + seen-check + one batch = 3 queries (+1 fetch).
 */
export async function runSource(env: Env, source: Source, now = Date.now()): Promise<SourceRunReport> {
  const t0 = Date.now();
  try {
    const state = await getSourceState(env.DB, source.name);
    const result = await source.run(env, state);

    if (result.items === null) {
      await sourceOkStatement(env.DB, source.name, { ...result, fetched: 0, fresh: 0 }, now).run();
      const r = { source: source.name, ok: true, notModified: true, ms: Date.now() - t0 };
      log('source.run', r);
      return r;
    }

    const items = result.items;
    const seen = await seenIds(env.DB, items.map((i) => i.id));
    const fresh = items.filter((i) => !seen.has(i.id));

    // First successful run for a source: store everything silently (keyword-scored, no AI,
    // no alerts), so a fresh deploy doesn't flood the chat or burn AI quota on old news.
    const baseline = !state || state.initialized === 0;

    const stmts: D1PreparedStatement[] = [];
    let pending = 0;
    let filtered = 0;
    for (const item of fresh) {
      const score = scoreItem(item);
      if (baseline) {
        // Social posts never become incidents without the AI (raw posts make bad titles).
        const s = item.typeHint === 'social' ? { ...score, isIncident: false } : score;
        stmts.push(...itemStatements(env.DB, item, s, 'baseline', 'baseline', now));
      } else if (score.reasons[0] === 'noise' || (item.typeHint === 'social' && !score.isIncident)) {
        // Pre-filter: webinars, funding news, sponsored posts... never reach the AI. Social posts
        // are mostly chatter: they also need a keyword incident signal.
        filtered++;
        stmts.push(...itemStatements(env.DB, item, { ...score, isIncident: false }, 'filtered', 'digest', now));
      } else {
        pending++;
        stmts.push(...itemStatements(env.DB, item, null, 'pending', 'digest', now));
      }
    }
    // Validators are saved in the same batch as the items: if the insert fails, the next run
    // re-fetches instead of getting a 304 and losing those items for good.
    stmts.push(sourceOkStatement(env.DB, source.name, { ...result, fetched: items.length, fresh: fresh.length }, now));
    await env.DB.batch(stmts);

    const r = { source: source.name, ok: true, baseline, fetched: items.length, fresh: fresh.length, pending, filtered, ms: Date.now() - t0 };
    log('source.run', r);
    return r;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logError('source.run', err, { source: source.name });
    await markSourceError(env.DB, source.name, message, now).catch(() => {});
    return { source: source.name, ok: false, error: message, ms: Date.now() - t0 };
  }
}
