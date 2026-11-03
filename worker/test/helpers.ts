import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { Item } from '../src/types';

export function fixture(name: string): string {
  return readFileSync(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)), 'utf8');
}

export function newsItem(title: string, summary = '', extra: Partial<Item> = {}): Item {
  return {
    id: `test:${title}`,
    source: 'test',
    title,
    url: 'https://example.com/a',
    publishedAt: Date.now(),
    summary,
    typeHint: 'news',
    meta: {},
    ...extra,
  };
}
