import { log, logError } from './log';
import { editMessageText, sendMessage, TelegramError } from './telegram/api';
import { loadMutes, muteStatus } from './mutes';
import { alertKeyboard, formatAlert, type IncidentView } from './telegram/format';
import type { Env } from './types';

// Rows come joined with their incident, so delivering N messages costs 1 + N D1 queries
// (+ N Telegram calls) — it shares the 50-subrequest budget with everything else.
interface OutboxRow extends Partial<IncidentView> {
  outbox_id: number;
  kind: 'alert' | 'edit' | 'text';
  incident_id: number | null;
  payload: string;
  attempts: number;
  telegram_message_id: number | null;
}

const MAX_ATTEMPTS = 5;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Send up to N queued Telegram messages, ~1/s. Waiting doesn't count toward the 10 ms CPU
 * limit. Leftovers go out on the next run.
 */
export async function drainOutbox(env: Env, now = Date.now()): Promise<{ sent: number; failed: number }> {
  const max = Number(env.MAX_TELEGRAM_SENDS_PER_RUN) || 4;
  const { results } = await env.DB.prepare(
    `SELECT o.id AS outbox_id, o.kind, o.incident_id, o.payload, o.attempts,
            i.id, i.title, i.summary, i.url, i.attack_type, i.sector, i.country, i.severity,
            i.source_count, i.sources, i.group_name, i.victim, i.vendor, i.telegram_message_id
     FROM outbox o LEFT JOIN incidents i ON i.id = o.incident_id
     WHERE o.sent_at IS NULL AND o.next_attempt_at <= ? AND o.attempts < ?
     ORDER BY o.id LIMIT ?`,
  )
    .bind(now, MAX_ATTEMPTS, max)
    .all<OutboxRow>();

  // Mutes are checked again at send time: an alert queued before a /mute must not go out.
  const mutes = results.some((r) => r.kind === 'alert') ? await loadMutes(env.DB, now) : [];

  let sent = 0;
  let failed = 0;
  let delivered = 0;
  for (const row of results) {
    if (row.kind === 'alert' && row.id) {
      const status = muteStatus({ attack_type: row.attack_type ?? null, group_name: row.group_name, vendor: row.vendor, victim: row.victim }, mutes, now);
      if (status) {
        // 'held' (quiet time) → into the digest; 'muted' (group/vendor) → silent.
        await env.DB.batch([
          env.DB.prepare('UPDATE outbox SET sent_at = ?, last_error = ? WHERE id = ?').bind(Date.now(), `skipped: ${status}`, row.outbox_id),
          env.DB.prepare('UPDATE incidents SET alert_state = ? WHERE id = ?').bind(status === 'held' ? 'digest' : 'muted', row.id),
        ]);
        continue;
      }
    }
    if (delivered++ > 0) await sleep(1100);
    try {
      const messageId = await deliver(env, row);
      const done = env.DB.prepare('UPDATE outbox SET sent_at = ?, attempts = attempts + 1 WHERE id = ?').bind(Date.now(), row.outbox_id);
      if (messageId && row.incident_id) {
        await env.DB.batch([
          done,
          env.DB.prepare("UPDATE incidents SET telegram_message_id = ?, alert_state = 'sent' WHERE id = ?").bind(messageId, row.incident_id),
        ]);
      } else {
        await done.run();
      }
      sent++;
    } catch (err) {
      failed++;
      const retryAfter = err instanceof TelegramError && err.retryAfter ? err.retryAfter * 1000 : 0;
      const backoff = Math.max(retryAfter, 60_000 * 2 ** row.attempts);
      await env.DB.prepare('UPDATE outbox SET attempts = attempts + 1, last_error = ?, next_attempt_at = ? WHERE id = ?')
        .bind(String(err instanceof Error ? err.message : err).slice(0, 300), Date.now() + backoff, row.outbox_id)
        .run();
      logError('outbox.fail', err, { outbox_id: row.outbox_id, kind: row.kind });
      // Rate-limited: stop this run, the rest will wait anyway.
      if (err instanceof TelegramError && err.code === 429) break;
    }
  }
  if (results.length) log('outbox.drain', { ok: true, sent, failed });
  return { sent, failed };
}

/** Returns the new Telegram message id for a sent alert, else null. */
async function deliver(env: Env, row: OutboxRow): Promise<number | null> {
  if (row.kind === 'text') {
    const p = JSON.parse(row.payload) as { text: string };
    await sendMessage(env, p.text);
    return null;
  }
  if (!row.id) return null; // incident deleted: nothing to send, mark done

  // Rendered from the *current* incident row, so a queued alert already shows the latest source count.
  const text = formatAlert(row as IncidentView);
  // Edits must resend the keyboard, otherwise Telegram removes the buttons.
  const reply_markup = alertKeyboard(row as IncidentView);
  if (row.kind === 'edit') {
    if (!row.telegram_message_id) return null;
    try {
      await editMessageText(env, row.telegram_message_id, text, { reply_markup });
    } catch (err) {
      // "message is not modified" is fine; anything else bubbles up for retry.
      if (!(err instanceof TelegramError && /not modified/i.test(err.message))) throw err;
    }
    return null;
  }
  const msg = await sendMessage(env, text, { reply_markup });
  return msg.message_id;
}
