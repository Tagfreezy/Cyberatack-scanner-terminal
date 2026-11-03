// Optional: Mastodon hashtag timelines (OFF by default, /toggle mastodon).
// infosec.exchange requires a logged-in user for hashtag timelines and serves empty hashtag
// RSS feeds (checked 2026-11-03), so this needs MASTODON_ACCESS_TOKEN (read-only app token
// from your account: Preferences → Development → New application, scope read:statuses).

import { hash } from '../http';
import type { Item } from '../types';
import { decodeEntities, parseDate } from '../xml';
import type { Source } from './types';

export const MASTODON_TAGS = ['ransomware', 'databreach', 'zeroday'] as const;

interface Status {
  id: string;
  url?: string | null;
  uri?: string;
  created_at?: string;
  language?: string | null;
  content?: string;
  sensitive?: boolean;
  account?: { acct?: string; bot?: boolean };
  reblog?: Status | null;
}

export function statusText(html: string): string {
  return decodeEntities(
    html
      .replace(/<br\s*\/?>/gi, '\n')
      .replace(/<\/p>\s*<p>/gi, '\n')
      .replace(/<[^>]+>/g, ' '),
  )
    .replace(/[ \t]+/g, ' ')
    .replace(/\s*\n\s*/g, '\n')
    .trim();
}

export function statusToItem(raw: Status): Item | null {
  const s = raw.reblog ?? raw;
  if (!s.id || !s.content) return null;
  if (s.language && !s.language.startsWith('en')) return null; // prompts/scoring are English
  const text = statusText(s.content);
  if (text.length < 40) return null;
  const firstLine = text.split('\n').find((l) => l.replace(/#\w+/g, '').trim().length > 20) ?? text;
  return {
    id: `mastodon:${s.id}`,
    source: 'mastodon',
    // Raw posts make poor incident titles; process.ts replaces it with the AI summary.
    title: firstLine.length > 160 ? `${firstLine.slice(0, 157)}…` : firstLine,
    url: s.url ?? s.uri ?? null,
    publishedAt: parseDate(s.created_at ?? ''),
    summary: text.slice(0, 600),
    typeHint: 'social',
    meta: { author: s.account?.acct },
  };
}

export const mastodonSource: Source = {
  name: 'mastodon',
  label: 'Mastodon',
  async run(env, state) {
    if (!env.MASTODON_ACCESS_TOKEN) throw new Error('MASTODON_ACCESS_TOKEN not set');
    // One hashtag per run, rotating (keeps each run small).
    const extra = state?.extra ? (JSON.parse(state.extra) as { next?: number }) : {};
    const idx = (extra.next ?? 0) % MASTODON_TAGS.length;
    const tag = MASTODON_TAGS[idx]!;
    const instance = (env.MASTODON_INSTANCE || 'infosec.exchange').replace(/^https?:\/\//, '').replace(/\/$/, '');
    const res = await fetch(`https://${instance}/api/v1/timelines/tag/${tag}?limit=20`, {
      headers: { Authorization: `Bearer ${env.MASTODON_ACCESS_TOKEN}`, 'User-Agent': env.USER_AGENT, Accept: 'application/json' },
      signal: AbortSignal.timeout(15000),
    });
    if (res.status === 401 || res.status === 403 || res.status === 422) throw new Error(`Mastodon ${res.status}: access token rejected`);
    if (!res.ok) throw new Error(`Mastodon HTTP ${res.status}`);
    const list = (await res.json()) as Status[];
    const seen = new Set<string>();
    const items: Item[] = [];
    for (const st of list) {
      const it = statusToItem(st);
      // Boosts of the same post across tags share an id; also skip exact-duplicate texts.
      const key = it ? hash(it.summary) : '';
      if (it && !seen.has(key)) {
        seen.add(key);
        items.push(it);
      }
    }
    return { items, extra: { next: idx + 1, tag } };
  },
};
