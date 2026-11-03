import type { Env } from '../types';

export class TelegramError extends Error {
  constructor(
    message: string,
    public code: number,
    public retryAfter: number | null,
  ) {
    super(message);
  }
}

interface TgResponse<T> {
  ok: boolean;
  result?: T;
  description?: string;
  error_code?: number;
  parameters?: { retry_after?: number };
}

export async function tg<T = unknown>(env: Env, method: string, body: Record<string, unknown>): Promise<T> {
  const res = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/${method}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(10000),
  });
  const data = (await res.json().catch(() => ({ ok: false, description: `HTTP ${res.status}` }))) as TgResponse<T>;
  if (!data.ok) {
    throw new TelegramError(
      `${method}: ${data.description ?? 'unknown error'}`,
      data.error_code ?? res.status,
      data.parameters?.retry_after ?? null,
    );
  }
  return data.result as T;
}

export interface SentMessage {
  message_id: number;
}

export function sendMessage(env: Env, text: string, extra: Record<string, unknown> = {}): Promise<SentMessage> {
  return tg<SentMessage>(env, 'sendMessage', {
    chat_id: env.TELEGRAM_CHAT_ID,
    text,
    parse_mode: 'HTML',
    link_preview_options: { is_disabled: true },
    ...extra,
  });
}

export function editMessageText(
  env: Env,
  messageId: number,
  text: string,
  extra: Record<string, unknown> = {},
): Promise<unknown> {
  return tg(env, 'editMessageText', {
    chat_id: env.TELEGRAM_CHAT_ID,
    message_id: messageId,
    text,
    parse_mode: 'HTML',
    link_preview_options: { is_disabled: true },
    ...extra,
  });
}
