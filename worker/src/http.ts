import type { Env, SourceState } from './types';

export class HttpError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

/**
 * GET with conditional headers (If-None-Match / If-Modified-Since) taken from the stored
 * source state. Returns `null` on 304 so callers can skip parsing entirely.
 */
export async function conditionalGet(
  env: Env,
  url: string,
  state: SourceState | null,
  extraHeaders: Record<string, string> = {},
  timeoutMs = 15000,
): Promise<Response | null> {
  const headers: Record<string, string> = {
    'User-Agent': env.USER_AGENT || 'cyberwatch/1.0',
    Accept: 'application/rss+xml, application/atom+xml, application/xml, application/json, text/xml;q=0.9, */*;q=0.8',
    ...extraHeaders,
  };
  if (state?.etag) headers['If-None-Match'] = state.etag;
  if (state?.last_modified) headers['If-Modified-Since'] = state.last_modified;

  const res = await fetch(url, { headers, signal: AbortSignal.timeout(timeoutMs) });
  if (res.status === 304) return null;
  if (!res.ok) {
    // Drain so the connection can be reused; ignore errors.
    await res.body?.cancel().catch(() => {});
    throw new HttpError(res.status, `HTTP ${res.status} from ${new URL(url).host}`);
  }
  return res;
}

/**
 * Read a feed body only until `maxItems` complete <item>/<entry> elements have arrived, then
 * cancel the download. Feeds are newest-first and we only use the top N, so decoding the
 * other 50–80% (Dark Reading 78 KB, ransomware.live 190 KB) is wasted CPU on the free plan.
 */
export async function readFeedHead(res: Response, maxItems: number, maxBytes = 512 * 1024): Promise<string> {
  if (!res.body) return res.text();
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let text = '';
  let bytes = 0;
  let closed = 0;
  let scanFrom = 0;
  try {
    while (bytes < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      const prevLen = text.length;
      text += decoder.decode(value, { stream: true });
      // Scan only new text, starting a few chars early in case a tag was split across
      // chunks, but never before the end of the last tag already counted.
      let i = text.indexOf('</', Math.max(scanFrom, prevLen - 8));
      for (; i !== -1; i = text.indexOf('</', i + 2)) {
        if (text.startsWith('</item>', i) || text.startsWith('</entry>', i)) {
          closed++;
          scanFrom = i + 7;
        }
      }
      if (closed >= maxItems) break;
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  return text;
}

export function validators(res: Response): { etag: string | null; lastModified: string | null } {
  return { etag: res.headers.get('etag'), lastModified: res.headers.get('last-modified') };
}

/** FNV-1a 32-bit, hex. Used for short, stable ids where a source has no guid. */
export function hash(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, '0');
}
