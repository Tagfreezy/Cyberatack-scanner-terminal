import { log, logError } from '../log';
import type { Env } from '../types';
import { sendMessage } from './api';
import {
  HELP,
  cmdLatest,
  cmdMute,
  cmdSensors,
  cmdSettings,
  cmdStats,
  cmdThreshold,
  cmdToggle,
  cmdToday,
  cmdUnmute,
  cmdWeek,
  onMoreInfo,
  onMute,
} from './commands';
import { escapeHtml, sourceLabel } from './format';

export interface TgUpdate {
  update_id: number;
  message?: { message_id: number; chat: { id: number }; from?: { id: number }; text?: string };
  callback_query?: {
    id: string;
    from: { id: number };
    message?: { message_id: number; chat: { id: number } };
    data?: string;
  };
}

/** Only the owner's chat is ever answered. Everyone else is silently ignored. */
export function isOwner(env: Env, chatId: number | undefined): boolean {
  return chatId !== undefined && String(chatId) === String(env.TELEGRAM_CHAT_ID).trim();
}

/** "/mute@MyBot 2h" → ["/mute", "2h"] */
export function parseCommand(text: string): { cmd: string; arg?: string } {
  const [first, ...rest] = text.trim().split(/\s+/);
  return { cmd: (first ?? '').toLowerCase().replace(/@.*$/, ''), arg: rest.join(' ') || undefined };
}

export async function handleUpdate(env: Env, update: TgUpdate): Promise<void> {
  const cb = update.callback_query;
  if (cb) {
    // Both the presser and the chat must be the owner.
    if (!isOwner(env, cb.from.id) || !isOwner(env, cb.message?.chat.id)) {
      log('webhook.ignored', { from: cb.from.id });
      return;
    }
    const [action, idStr] = (cb.data ?? '').split(':');
    const id = Number(idStr);
    if (!Number.isInteger(id)) return;
    if (action === 'info') await onMoreInfo(env, cb.id, id, cb.message?.message_id);
    else if (action === 'mute') await onMute(env, cb.id, id);
    return;
  }

  const msg = update.message;
  if (!msg || !isOwner(env, msg.chat.id)) {
    if (msg) log('webhook.ignored', { chat: msg.chat.id });
    return;
  }
  const { cmd, arg } = parseCommand(msg.text ?? '');
  let replies: string[] | null = null;
  try {
    switch (cmd) {
      case '/start':
      case '/help':
        replies = [HELP];
        break;
      case '/status':
        replies = [await statusText(env)];
        break;
      case '/latest':
        replies = await cmdLatest(env, arg);
        break;
      case '/today':
        replies = await cmdToday(env);
        break;
      case '/stats':
        replies = await cmdStats(env);
        break;
      case '/week':
        replies = await cmdWeek(env);
        break;
      case '/mute':
        replies = await cmdMute(env, arg);
        break;
      case '/unmute':
        replies = await cmdUnmute(env, arg);
        break;
      case '/settings':
        replies = await cmdSettings(env);
        break;
      case '/sensors':
        replies = await cmdSensors(env);
        break;
      case '/toggle':
        replies = await cmdToggle(env, arg);
        break;
      case '/threshold':
        replies = await cmdThreshold(env, arg);
        break;
      default:
        if (cmd.startsWith('/')) replies = ['Unknown command. /help lists them all.'];
    }
  } catch (err) {
    logError('command', err, { cmd });
    replies = ['⚠️ Something went wrong with that command. Try again in a minute.'];
  }
  // Direct replies (not via the outbox): the user triggered them, so they're expected now.
  for (const r of replies ?? []) await sendMessage(env, r);
}

/** 3× each source's schedule (see scheduler.ts): news 20 min, ransomware.live 15 min, KEV 1 h. */
export function staleAfterMs(source: string): number {
  return ['cisa-kev', 'sans-isc', 'threatfox'].includes(source) ? 3 * 3600_000 : 3600_000;
}

function ago(ms: number | null): string {
  if (!ms) return 'never';
  const m = Math.round((Date.now() - ms) / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  return h < 48 ? `${h}h ago` : `${Math.round(h / 24)}d ago`;
}

async function statusText(env: Env): Promise<string> {
  const { results } = await env.DB.prepare(
    'SELECT source, last_ok, last_error, last_error_at FROM source_state ORDER BY source',
  ).all<{ source: string; last_ok: number | null; last_error: string | null; last_error_at: number | null }>();
  const c = await env.DB.prepare(
    `SELECT (SELECT COUNT(*) FROM incidents WHERE first_seen > ?1) AS today,
            (SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL AND attempts < 5) AS pending,
            (SELECT COUNT(*) FROM items WHERE status = 'pending') AS queue,
            (SELECT COUNT(*) FROM incidents WHERE first_seen > ?1 AND source_count > 1) AS merged,
            (SELECT value FROM settings WHERE key = 'ai_paused_until') AS ai_paused_until`,
  )
    .bind(Date.now() - 86_400_000)
    .first<{ today: number; pending: number; queue: number; merged: number; ai_paused_until: string | null }>();

  const lines = ['<b>Sources</b>'];
  for (const r of results) {
    const failing = (r.last_error_at ?? 0) > (r.last_ok ?? 0);
    // A run killed by Cloudflare (e.g. CPU limit) never records an error, so "no success for
    // 3× the normal interval" also counts as unhealthy.
    const stale = Date.now() - (r.last_ok ?? 0) > staleAfterMs(r.source);
    const detail = failing
      ? `error ${ago(r.last_error_at)}: ${escapeHtml(r.last_error ?? '')}`
      : stale
        ? `no successful run for ${ago(r.last_ok).replace(' ago', '')}`
        : `ok ${ago(r.last_ok)}`;
    lines.push(`${failing || stale ? '🔴' : '🟢'} ${escapeHtml(sourceLabel(r.source))} — ${detail}`);
  }
  if (!results.length) lines.push('(no runs yet)');
  const pausedUntil = Number(c?.ai_paused_until ?? 0);
  const ai =
    pausedUntil > Date.now()
      ? `🟠 AI paused until ${new Date(pausedUntil).toISOString().slice(11, 16)} UTC (keyword fallback active)`
      : '🟢 AI classification active';
  lines.push('', ai);
  lines.push(
    `Incidents (24h): ${c?.today ?? 0} (${c?.merged ?? 0} multi-source) · waiting for AI: ${c?.queue ?? 0} · queued messages: ${c?.pending ?? 0}`,
  );
  return lines.join('\n');
}
