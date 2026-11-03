import { log } from '../log';
import type { Env } from '../types';
import { sendMessage } from './api';
import { escapeHtml, sourceLabel } from './format';

export interface TgUpdate {
  update_id: number;
  message?: { message_id: number; chat: { id: number }; from?: { id: number }; text?: string };
  callback_query?: { id: string; from: { id: number }; message?: { chat: { id: number } }; data?: string };
}

/** Only the owner's chat is ever answered. Everyone else is silently ignored. */
export function isOwner(env: Env, chatId: number | undefined): boolean {
  return chatId !== undefined && String(chatId) === String(env.TELEGRAM_CHAT_ID).trim();
}

const HELP = [
  '<b>CyberWatch</b> — live cyberattack monitor',
  '',
  '/status — source health and counters',
  '/help — this message',
  '',
  'Alerts are AI-classified; the same attack from several outlets becomes one alert that',
  'gets updated ("📰 3 sources") instead of new messages.',
  '',
  'More commands (/latest, /today, /mute, …) arrive in phase 3.',
].join('\n');

export async function handleUpdate(env: Env, update: TgUpdate): Promise<void> {
  const msg = update.message;
  if (!msg || !isOwner(env, msg.chat.id)) {
    if (msg) log('webhook.ignored', { chat: msg.chat.id });
    return;
  }
  const cmd = (msg.text ?? '').trim().split(/\s+/)[0]!.toLowerCase().replace(/@.*$/, '');
  switch (cmd) {
    case '/start':
    case '/help':
      await sendMessage(env, HELP);
      return;
    case '/status':
      await sendMessage(env, await statusText(env));
      return;
    default:
      return;
  }
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
    const healthy = (r.last_ok ?? 0) >= (r.last_error_at ?? 0);
    const detail = healthy ? `ok ${ago(r.last_ok)}` : `error ${ago(r.last_error_at)}: ${escapeHtml(r.last_error ?? '')}`;
    lines.push(`${healthy ? '🟢' : '🔴'} ${escapeHtml(sourceLabel(r.source))} — ${detail}`);
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
