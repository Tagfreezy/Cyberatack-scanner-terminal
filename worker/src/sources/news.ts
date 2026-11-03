import { conditionalGet, hash, validators } from '../http';
import type { Item } from '../types';
import { parseDate, parseFeed, type RawFeedEntry } from '../xml';
import type { Source } from './types';

export const NEWS_FEEDS = [
  { name: 'bleepingcomputer', label: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/' },
  { name: 'therecord', label: 'The Record', url: 'https://therecord.media/feed' },
  { name: 'thehackernews', label: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews' },
  { name: 'securityweek', label: 'SecurityWeek', url: 'https://www.securityweek.com/feed/' },
] as const;

export function newsEntryToItem(source: string, e: RawFeedEntry): Item | null {
  if (!e.title) return null;
  const stable = e.guid || e.link || e.title;
  return {
    id: `${source}:${hash(stable)}`,
    source,
    title: e.title,
    url: e.link || null,
    publishedAt: parseDate(e.pubDate),
    summary: e.description.slice(0, 600),
    typeHint: 'news',
    meta: { categories: e.categories.slice(0, 8), author: e.creator || undefined },
  };
}

export function parseNewsFeed(source: string, xml: string, max: number): Item[] {
  return parseFeed(xml, max)
    .map((e) => newsEntryToItem(source, e))
    .filter((x): x is Item => x !== null);
}

export const newsSources: Source[] = NEWS_FEEDS.map((f) => ({
  name: f.name,
  label: f.label,
  async run(env, state) {
    const res = await conditionalGet(env, f.url, state);
    if (!res) return { items: null };
    const xml = await res.text();
    const max = Number(env.RSS_MAX_ITEMS) || 20;
    return { items: parseNewsFeed(f.name, xml, max), ...validators(res) };
  },
}));
