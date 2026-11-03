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
