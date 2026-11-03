import { conditionalGet, hash, readFeedHead, validators } from '../http';
import type { Item } from '../types';
import { parseDate, parseFeed, type RawFeedEntry } from '../xml';
import type { Source } from './types';

// The free "v2" API (api.ransomware.live/v2) was retired: every path now returns the
// website's 404 page (checked 2026-11-03). Default = the public RSS feed, which has
// victim, group and country. With RANSOMWARE_LIVE_API_KEY set we use the PRO API.
export const RL_RSS_URL = 'https://www.ransomware.live/rss.xml';
export const RL_PRO_BASE = 'https://api-pro.ransomware.live';

const TITLE_RE = /^\W*(.+?)\s+has just published a new victim\s*:\s*(.+)$/u;

/** "https://www.ransomware.live/id/<base64>" → "<base64>" (same id the PRO API returns). */
function rlId(link: string): string | null {
  const m = link.match(/\/id\/([A-Za-z0-9+/=_-]+)/);
  return m ? m[1]! : null;
}

export function rlEntryToItem(e: RawFeedEntry): Item | null {
  const m = e.title.match(TITLE_RE);
  const group = m ? m[1]!.trim() : undefined;
  const victim = m ? m[2]!.trim() : e.title;
  if (!victim) return null;
  const country = e.categories.find((c) => /^[A-Z]{2}$/.test(c));
  const desc = e.description && e.description !== 'N/A' ? e.description : '';
  return {
    id: `rl:${rlId(e.link) ?? hash(e.guid || e.title)}`,
    source: 'ransomware.live',
    title: group ? `${group} claims attack on ${victim}` : victim,
    url: e.link || null,
    publishedAt: parseDate(e.pubDate),
    summary: desc.slice(0, 600),
    typeHint: 'leak',
    meta: { group, victim, country },
  };
}

export function parseRansomwareLiveRss(xml: string, max: number): Item[] {
  return parseFeed(xml, max)
    .map(rlEntryToItem)
    .filter((x): x is Item => x !== null);
}

interface ProVictim {
  id?: string;
  victim?: string;
  group?: string;
  country?: string;
  activity?: string;
  attackdate?: string;
  discovered?: string;
  permalink?: string;
  description?: string;
  website?: string;
}

export function proVictimToItem(v: ProVictim): Item | null {
  if (!v.victim) return null;
  const group = v.group?.trim();
  return {
    id: `rl:${v.id ?? hash(`${v.victim}@${group ?? ''}`)}`,
    source: 'ransomware.live',
    title: group ? `${group} claims attack on ${v.victim}` : v.victim,
    url: v.permalink ?? null,
    publishedAt: parseDate(v.discovered ?? v.attackdate ?? ''),
    summary: (v.description ?? '').slice(0, 600),
    typeHint: 'leak',
    meta: {
      group,
      victim: v.victim,
      country: v.country && /^[A-Za-z]{2}$/.test(v.country) ? v.country.toUpperCase() : undefined,
      sector: v.activity && v.activity !== 'Not Found' ? v.activity : undefined,
    },
  };
}

export const ransomwareLiveSource: Source = {
  name: 'ransomware.live',
  label: 'ransomware.live',
  async run(env, state) {
    const max = 25; // ~65 posts/day, checked every 15 min → 1–3 new per run
    if (env.RANSOMWARE_LIVE_API_KEY) {
      const res = await conditionalGet(env, `${RL_PRO_BASE}/victims/recent`, null, {
        'X-API-KEY': env.RANSOMWARE_LIVE_API_KEY,
        Accept: 'application/json',
      });
      const body = (await res!.json()) as ProVictim[] | { victims?: ProVictim[] };
      const list = Array.isArray(body) ? body : (body.victims ?? []);
      return {
        items: list
          .slice(0, max)
          .map(proVictimToItem)
          .filter((x): x is Item => x !== null),
      };
    }
    const res = await conditionalGet(env, RL_RSS_URL, state);
    if (!res) return { items: null };
    return { items: parseRansomwareLiveRss(await readFeedHead(res, max), max), ...validators(res) };
  },
};
