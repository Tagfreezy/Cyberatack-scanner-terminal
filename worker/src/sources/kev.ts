import { conditionalGet, validators } from '../http';
import type { Item } from '../types';
import type { Source } from './types';

export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

// The KEV catalog is ~1.8 MB, but it is sorted newest-first. Instead of JSON.parse on
// everything (too much CPU for the free plan), we stream only the first ~96 KB, cancel
// the rest, and pull complete objects out of that prefix.
const HEAD_BYTES = 96 * 1024;
const MAX_ENTRIES = 30;

export interface KevVuln {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  knownRansomwareCampaignUse?: string;
  dueDate?: string;
}

export interface KevHead {
  count: number | null;
  dateReleased: string | null;
  vulns: KevVuln[];
}

/** Parse header fields + first `max` complete vulnerability objects from a (possibly truncated) KEV document. */
export function parseKevHead(text: string, max = MAX_ENTRIES): KevHead {
  const count = text.match(/"count"\s*:\s*(\d+)/);
  const released = text.match(/"dateReleased"\s*:\s*"([^"]+)"/);
  const vulns: KevVuln[] = [];

  const key = text.indexOf('"vulnerabilities"');
  let i = key === -1 ? -1 : text.indexOf('[', key);
  if (i !== -1) {
    i++;
    while (vulns.length < max) {
      // skip whitespace and commas
      while (i < text.length && /[\s,]/.test(text[i]!)) i++;
      if (i >= text.length || text[i] !== '{') break;
      const end = matchObject(text, i);
      if (end === -1) break; // truncated object at the end of our prefix
      try {
        vulns.push(JSON.parse(text.slice(i, end + 1)) as KevVuln);
      } catch {
        /* skip a malformed entry, keep going */
      }
      i = end + 1;
    }
  }
  return {
    count: count ? Number(count[1]) : null,
    dateReleased: released ? released[1]! : null,
    vulns,
  };
}

/** Index of the '}' matching the '{' at `start`, or -1 if the text ends first. String-aware. */
function matchObject(text: string, start: number): number {
  let depth = 0;
  let inStr = false;
  for (let i = start; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (inStr) {
      if (c === 92) i++; // backslash: skip escaped char
      else if (c === 34) inStr = false;
      continue;
    }
    if (c === 34) inStr = true;
    else if (c === 123) depth++;
    else if (c === 125 && --depth === 0) return i;
  }
  return -1;
}

async function readHead(res: Response, maxBytes: number): Promise<string> {
  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  let text = '';
  let bytes = 0;
  try {
    while (bytes < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      text += decoder.decode(value, { stream: true });
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  return text;
}

export function kevToItem(v: KevVuln): Item {
  const known = (v.knownRansomwareCampaignUse ?? '').toLowerCase() === 'known';
  return {
    id: `kev:${v.cveID}`,
    source: 'cisa-kev',
    title: `${v.cveID}: ${v.vulnerabilityName}`,
    url: `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
    publishedAt: Date.parse(`${v.dateAdded}T00:00:00Z`) || null,
    summary: v.shortDescription,
    typeHint: 'kev',
    meta: { vendor: v.vendorProject, product: v.product, cve: v.cveID, knownRansomware: known },
  };
}

interface KevExtra {
  count: number | null;
  dateReleased: string | null;
}

export const kevSource: Source = {
  name: 'cisa-kev',
  label: 'CISA KEV',
  async run(env, state) {
    const res = await conditionalGet(env, KEV_URL, state, {}, 25000);
    if (!res) return { items: null };
    const head = parseKevHead(await readHead(res, HEAD_BYTES));
    const extra: KevExtra = { count: head.count, dateReleased: head.dateReleased };

    // Second guard (the user asked for it): same count + dateReleased = unchanged.
    const prev = state?.extra ? (JSON.parse(state.extra) as KevExtra) : null;
    if (prev && prev.count === head.count && prev.dateReleased === head.dateReleased) {
      return { items: null, ...validators(res), extra };
    }
    if (head.vulns.length === 0) throw new Error('KEV: no entries parsed (format changed?)');
    return { items: head.vulns.map(kevToItem), ...validators(res), extra };
  },
};
