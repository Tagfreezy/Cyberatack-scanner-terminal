import { log, logError } from './log';
import { drainOutbox } from './outbox';
import { runSource } from './pipeline';
import { backfillVectors, processPending } from './process';
import { ALL_SOURCES, runScheduled } from './scheduler';
import { sendMessage, tg } from './telegram/api';
import { formatAlert } from './telegram/format';
import { handleUpdate, type TgUpdate } from './telegram/webhook';
import { classify, embed } from './ai';
import { cosine } from './dedupe';
import type { Env, Item } from './types';

const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data, null, 2), { status, headers: { 'Content-Type': 'application/json' } });

/** Constant-time string compare, so tokens can't be guessed via response timing. */
function safeEqual(a: string, b: string): boolean {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function bearerOk(req: Request, env: Env): boolean {
  const h = req.headers.get('Authorization') ?? '';
  return h.startsWith('Bearer ') && safeEqual(h.slice(7), env.API_TOKEN ?? '');
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;

    if (path === '/' || path === '/health') return new Response('cyberwatch ok\n');

    // --- Telegram webhook -------------------------------------------------------------
    if (path === '/telegram/webhook' && req.method === 'POST') {
      const secret = req.headers.get('X-Telegram-Bot-Api-Secret-Token') ?? '';
      if (!safeEqual(secret, env.TELEGRAM_WEBHOOK_SECRET ?? '')) return new Response('forbidden', { status: 403 });
      const update = (await req.json().catch(() => null)) as TgUpdate | null;
      // Answer Telegram immediately; do the work after the response is sent.
      if (update) ctx.waitUntil(handleUpdate(env, update).catch((e) => logError('webhook', e)));
      return new Response('ok');
    }

    // --- Everything below needs the bearer token ----------------------------------------
    if (path.startsWith('/admin/') || path.startsWith('/api/')) {
      if (!bearerOk(req, env)) return json({ error: 'unauthorized' }, 401);
    }

    // Send a sample alert straight to Telegram (phase-1 smoke test).
    if (path === '/admin/test-alert' && req.method === 'POST') {
      const text = formatAlert({
        id: 0,
        title: 'CyberWatch test alert — if you can read this, alerts work',
        summary: 'This is a test message from your CyberWatch worker. No real incident.',
        url: 'https://github.com/',
        attack_type: 'ransomware',
        sector: 'Testing',
        country: 'CH',
        severity: 4,
        source_count: 1,
        sources: JSON.stringify(['cyberwatch']),
        group_name: 'test-group',
      });
      const msg = await sendMessage(env, text);
      return json({ ok: true, message_id: msg.message_id });
    }

    // Run one source (or all) right now, then drain the outbox. ?source=name|all
    if (path === '/admin/run' && req.method === 'POST') {
      const which = url.searchParams.get('source') ?? 'all';
      const list = which === 'all' ? ALL_SOURCES : ALL_SOURCES.filter((s) => s.name === which);
      if (!list.length) return json({ error: `unknown source; use one of: ${ALL_SOURCES.map((s) => s.name).join(', ')}` }, 400);
      const reports = [];
      for (const s of list) reports.push(await runSource(env, s));
      const processed = await processPending(env);
      const outbox = await drainOutbox(env);
      return json({ reports, processed, outbox });
    }

    // Classify/dedupe a few pending items now (same as one cron tick's stage 2).
    if (path === '/admin/process' && req.method === 'POST') {
      const processed = await processPending(env);
      const backfilled = url.searchParams.has('backfill') ? await backfillVectors(env) : undefined;
      const outbox = await drainOutbox(env);
      return json({ processed, backfilled, outbox });
    }

    // Point Telegram at this worker + register commands. Saves pasting the bot token into curl.
    if (path === '/admin/setup-webhook' && req.method === 'POST') {
      const hook = `${url.origin}/telegram/webhook`;
      await tg(env, 'setWebhook', {
        url: hook,
        secret_token: env.TELEGRAM_WEBHOOK_SECRET,
        allowed_updates: ['message', 'callback_query'],
        drop_pending_updates: true,
      });
      await tg(env, 'setMyCommands', { commands: BOT_COMMANDS });
      const info = await tg(env, 'getWebhookInfo', {});
      return json({ ok: true, webhook: hook, info });
    }

    // Try the classifier/embeddings on arbitrary items, e.g. to compare models or tune thresholds.
    // Body: { model?, items?: Item-like[], embed?: string[] }
    if (path === '/admin/ai-eval' && req.method === 'POST') {
      const body = (await req.json()) as { model?: string; items?: Partial<Item>[]; embed?: string[]; embedModel?: string };
      const model = body.model ?? env.AI_MODEL;
      const results = [];
      for (const raw of body.items ?? []) {
        const item: Item = { id: 'eval', source: 'eval', title: '', url: null, publishedAt: null, summary: '', typeHint: 'news', meta: {}, ...raw };
        const t0 = Date.now();
        let out: unknown;
        try {
          out = await classify(env, item, model);
        } catch (e) {
          out = { error: e instanceof Error ? e.message : String(e) };
        }
        results.push({ title: item.title, ms: Date.now() - t0, out });
      }
      let similarity: number[][] | undefined;
      let dims: number | undefined;
      if (body.embed?.length) {
        const vecs = await embed({ ...env, EMBED_MODEL: body.embedModel ?? env.EMBED_MODEL }, body.embed);
        dims = vecs[0]?.length;
        similarity = vecs.map((a) => vecs.map((b) => Math.round(cosine(a, b) * 1000) / 1000));
      }
      return json({ model, results, dims, similarity });
    }

    if (path === '/admin/status' && req.method === 'GET') {
      const sources = await env.DB.prepare('SELECT * FROM source_state ORDER BY source').all();
      const counts = await env.DB.prepare(
        `SELECT (SELECT COUNT(*) FROM items) AS items, (SELECT COUNT(*) FROM incidents) AS incidents,
                (SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL) AS outbox_pending`,
      ).first();
      return json({ counts, sources: sources.results });
    }

    return json({ error: 'not found' }, 404);
  },

  // Awaited directly (not waitUntil): scheduled handlers get up to 15 min of wall time, but
  // waitUntil work may be cut off ~30 s after the handler returns. AI items take ~5 s each.
  async scheduled(controller: ScheduledController, env: Env): Promise<void> {
    log('scheduled', { cron: controller.cron });
    await runScheduled(env, controller.scheduledTime).catch((e) => logError('tick', e));
  },
} satisfies ExportedHandler<Env>;

// Phase 1 registers the commands that exist now; phase 3 extends this list.
export const BOT_COMMANDS = [
  { command: 'start', description: 'Check that the bot is alive' },
  { command: 'help', description: 'Show available commands' },
  { command: 'status', description: 'Source health and counters' },
];
