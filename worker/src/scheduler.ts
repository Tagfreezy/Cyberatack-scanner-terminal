import { log, logError } from './log';
import { drainOutbox } from './outbox';
import { runSource } from './pipeline';
import { backfillVectors, clearRecentVectors, expireVectors, processPending } from './process';
import { maybeSendReports } from './reports';
import { kevSource } from './sources/kev';
import { newsSources } from './sources/news';
import { ransomwareLiveSource } from './sources/ransomwarelive';
import type { Source } from './sources/types';
import type { Env } from './types';

export const ALL_SOURCES: Source[] = [...newsSources, ransomwareLiveSource, kevSource];

/**
 * The single every-5-minutes cron calls this. Each tick ("slot" 0-11 within the hour) runs only a
 * small slice of the work, so no single invocation does much parsing:
 *   - one news feed per tick, rotating → each feed every 20 min
 *   - ransomware.live every 15 min (well within its rate limit)
 *   - CISA KEV once an hour (304 / unchanged-check makes most runs free)
 * Budget per tick (free plan: 50 subrequests shared by D1, fetch, AI, Vectorize; a
 * db.batch counts as one): ≤2 sources × 4 + AI processing ≈ 21 + backfill 4 (2×/h)
 * + outbox ≤ 9 + cleanup ≈ 4 (once a day) → worst case ≈ 46.
 * Slots are computed from the trigger's scheduledTime (not Date.now()), so a delayed run
 * still does the job it was meant for.
 */
export function dueSources(scheduledTime: number): Source[] {
  const slot = Math.floor(new Date(scheduledTime).getUTCMinutes() / 5); // 0..11
  const due: Source[] = [newsSources[slot % newsSources.length]!];
  if (slot % 3 === 1) due.push(ransomwareLiveSource);
  if (slot === 2) due.push(kevSource);
  return due;
}

export function isCleanupSlot(scheduledTime: number): boolean {
  const d = new Date(scheduledTime);
  return d.getUTCHours() === 3 && d.getUTCMinutes() < 5;
}

export async function runScheduled(env: Env, scheduledTime: number): Promise<void> {
  const due = dueSources(scheduledTime);
  log('tick', { slot: Math.floor(new Date(scheduledTime).getUTCMinutes() / 5), sources: due.map((s) => s.name) });

  // allSettled + runSource never throwing = one broken source can't stop the others.
  await Promise.allSettled(due.map((s) => runSource(env, s)));
  // Each later stage is isolated too: a failure is logged, the next stage still runs.
  await step('process', () => processPending(env));
  if (slot(scheduledTime) % 6 === 0) await step('backfill', () => backfillVectors(env));
  // Digest (daily) / weekly report: only does anything during the 08:xx Zurich hour.
  await step('reports', () => maybeSendReports(env, scheduledTime));
  await step('outbox', () => drainOutbox(env));
  if (isCleanupSlot(scheduledTime)) await step('cleanup', () => cleanup(env));
}

const slot = (t: number) => Math.floor(new Date(t).getUTCMinutes() / 5);

async function step(name: string, fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn();
  } catch (err) {
    logError(name, err);
  }
}

/** Daily retention so the free 5 GB D1 and 5M Vectorize dimensions never fill up. */
async function cleanup(env: Env): Promise<void> {
  const day = 86_400_000;
  const now = Date.now();
  await expireVectors(env, now);
  await clearRecentVectors(env, now);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM items WHERE status IN ('filtered', 'rejected') AND created_at < ?").bind(now - 14 * day),
    env.DB.prepare('DELETE FROM outbox WHERE sent_at IS NOT NULL AND sent_at < ?').bind(now - 7 * day),
    env.DB.prepare('DELETE FROM sensor_snapshots WHERE created_at < ?').bind(now - 30 * day),
  ]);
  log('cleanup', { ok: true });
}
