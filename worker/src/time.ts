// Local-time helpers. Cron runs in UTC; Zurich is UTC+1 in winter and UTC+2 in summer, so
// "08:00 Zurich" is 07:00 or 06:00 UTC depending on the date. Instead of hard-coding cron
// hours (which breaks twice a year), every 5-min tick asks Intl what time it is in Zurich.

export interface LocalParts {
  date: string; // YYYY-MM-DD (local)
  year: number;
  month: number; // 1-12
  day: number;
  hour: number; // 0-23
  minute: number;
  weekday: number; // 1 = Monday … 7 = Sunday
}

const WEEKDAYS: Record<string, number> = { Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6, Sun: 7 };

export function localParts(ts: number, timeZone: string): LocalParts {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    weekday: 'short',
    hourCycle: 'h23',
  }).formatToParts(new Date(ts));
  const get = (t: string) => parts.find((p) => p.type === t)?.value ?? '';
  const year = Number(get('year'));
  const month = Number(get('month'));
  const day = Number(get('day'));
  return {
    date: `${get('year')}-${get('month')}-${get('day')}`,
    year,
    month,
    day,
    hour: Number(get('hour')) % 24,
    minute: Number(get('minute')),
    weekday: WEEKDAYS[get('weekday')] ?? 1,
  };
}

/** UTC offset of `timeZone` at instant `ts`, in ms (Zurich: +1h or +2h). */
export function tzOffset(ts: number, timeZone: string): number {
  const p = localParts(ts, timeZone);
  const asUtc = Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute);
  return asUtc - Math.floor(ts / 60_000) * 60_000;
}

/** UTC instant of local midnight of the local day containing `ts`. Exact across DST changes. */
export function localMidnight(ts: number, timeZone: string): number {
  const p = localParts(ts, timeZone);
  const wall = Date.UTC(p.year, p.month - 1, p.day);
  // Two passes: the offset at midnight can differ from the offset "now" on DST days.
  let guess = wall - tzOffset(ts, timeZone);
  guess = wall - tzOffset(guess, timeZone);
  return guess;
}

/** ISO-8601 week key, e.g. "2026-W45", for once-per-week guards. */
export function isoWeekKey(p: LocalParts): string {
  const d = new Date(Date.UTC(p.year, p.month - 1, p.day));
  const dow = p.weekday; // 1..7
  d.setUTCDate(d.getUTCDate() + 4 - dow); // Thursday of this week decides the year
  const yearStart = Date.UTC(d.getUTCFullYear(), 0, 1);
  const week = Math.ceil(((d.getTime() - yearStart) / 86_400_000 + 1) / 7);
  return `${d.getUTCFullYear()}-W${String(week).padStart(2, '0')}`;
}

/** "30m", "2h", "1d", "1w", "90" (minutes) → ms. null if invalid or > 30 days. */
export function parseDuration(s: string | undefined): number | null {
  if (!s) return null;
  const m = s.trim().toLowerCase().match(/^(\d+(?:\.\d+)?)\s*(m|min|mins|minutes?|h|hrs?|hours?|d|days?|w|weeks?)?$/);
  if (!m) return null;
  const n = Number(m[1]);
  const unit = (m[2] ?? 'm')[0];
  const ms = n * ({ m: 60_000, h: 3_600_000, d: 86_400_000, w: 604_800_000 } as Record<string, number>)[unit!]!;
  if (!Number.isFinite(ms) || ms <= 0 || ms > 30 * 86_400_000) return null;
  return Math.round(ms);
}

/** Human duration: 5400000 → "1h 30m". */
export function formatDuration(ms: number): string {
  const min = Math.max(1, Math.round(ms / 60_000));
  const d = Math.floor(min / 1440);
  const h = Math.floor((min % 1440) / 60);
  const m = min % 60;
  return [d && `${d}d`, h && `${h}h`, m && `${m}m`].filter(Boolean).join(' ') || '0m';
}
