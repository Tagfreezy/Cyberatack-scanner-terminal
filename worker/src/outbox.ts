import { log, logError } from './log';
import { editMessageText, sendMessage, TelegramError } from './telegram/api';
import { formatAlert, type IncidentView } from './telegram/format';
import type { Env } from './types';

interface OutboxRow {
  id: number;
  kind: 'alert' | 'edit' | 'text';
  incident_id: number | null;
  payload: string;
  attempts: number;
}

const MAX_ATTEMPTS = 5;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Send up to N queued Telegram messages, ~1/s. Waiting doesn't count toward the 10 ms CPU
 * limit, and capping N keeps us far below 50 subrequests. Leftovers go out next run.
 */
export async function drainOutbox(env: Env, now = Date.now()): Promise<{ sent: number; failed: number }> {
  const max = Number(env.MAX_TELEGRAM_SENDS_PER_RUN) || 5;
  const { results } = await env.DB.prepare(
    `SELECT id, kind, incident_id, payload, attempts FROM outbox
     WHERE sent_at IS NULL AND next_attempt_at <= ? AND attempts < ?
     ORDER BY id LIMIT ?`,
  )
    .bind(now, MAX_ATTEMPTS, max)
    .all<OutboxRow>();

  let sent = 0;
  let failed = 0;
  for (const [i, row] of results.entries()) {
    if (i > 0) await sleep(1100);
    try {
      await deliver(env, row);
      await env.DB.prepare('UPDATE outbox SET sent_at = ?, attempts = attempts + 1 WHERE id = ?')
        .bind(Date.now(), row.id)
        .run();
      sent++;
    } catch (err) {
      failed++;
      const retryAfter = err instanceof TelegramError && err.retryAfter ? err.retryAfter * 1000 : 0;
      const backoff = Math.max(retryAfter, 60_000 * 2 ** row.attempts);
      await env.DB.prepare(
        'UPDATE outbox SET attempts = attempts + 1, last_error = ?, next_attempt_at = ? WHERE id = ?',
      )
        .bind(String(err instanceof Error ? err.message : err).slice(0, 300), Date.now() + backoff, row.id)
        .run();
      logError('outbox.fail', err, { outbox_id: row.id, kind: row.kind });
      // Rate-limited: stop this run, the rest will wait anyway.
      if (err instanceof TelegramError && err.code === 429) break;
    }
  }
  if (results.length) log('outbox.drain', { ok: true, sent, failed });
  return { sent, failed };
}

async function loadIncident(env: Env, id: number): Promise<(IncidentView & { telegram_message_id: number | null }) | null> {
  return env.DB.prepare(
    `SELECT id, title, summary, url, attack_type, sector, country, severity, source_count, sources,
            group_name, victim, telegram_message_id FROM incidents WHERE id = ?`,
  )
    .bind(id)
    .first();
}

async function deliver(env: Env, row: OutboxRow): Promise<void> {
  if (row.kind === 'text') {
    const p = JSON.parse(row.payload) as { text: string };
    await sendMessage(env, p.text);
    return;
  }
  const inc = row.incident_id ? await loadIncident(env, row.incident_id) : null;
  if (!inc) return; // incident deleted: nothing to send, mark done

  // Built from the *current* incident row, so a queued alert already shows the latest source count.
  const text = formatAlert(inc);
  if (row.kind === 'edit' && inc.telegram_message_id) {
    try {
      await editMessageText(env, inc.telegram_message_id, text);
    } catch (err) {
      // "message is not modified" is fine; anything else bubbles up for retry.
      if (!(err instanceof TelegramError && /not modified/i.test(err.message))) throw err;
    }
    return;
  }
  const msg = await sendMessage(env, text);
  await env.DB.prepare("UPDATE incidents SET telegram_message_id = ?, alert_state = 'sent' WHERE id = ?")
    .bind(msg.message_id, inc.id)
    .run();
}
