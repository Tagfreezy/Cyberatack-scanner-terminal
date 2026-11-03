import { describe, expect, it } from 'vitest';
import { muteStatus, muteTarget, type Mute } from '../src/mutes';
import { alertKeyboard, formatDigest, formatIncidentLine, formatWeekly, splitMessage, trend, type IncidentView } from '../src/telegram/format';
import { isOwner, parseCommand } from '../src/telegram/webhook';
import { formatDuration, isoWeekKey, localMidnight, localParts, parseDuration } from '../src/time';
import type { Env } from '../src/types';

const TZ = 'Europe/Zurich';

describe('Zurich time, DST-safe (expected values from Python zoneinfo)', () => {
  it('08:00 Zurich is 07:00 UTC in winter and 06:00 UTC in summer', () => {
    expect(localParts(Date.UTC(2026, 0, 15, 7, 0), TZ)).toMatchObject({ date: '2026-01-15', hour: 8, minute: 0, weekday: 4 });
    expect(localParts(Date.UTC(2026, 6, 15, 6, 0), TZ)).toMatchObject({ date: '2026-07-15', hour: 8, minute: 0, weekday: 3 });
    // the "wrong" UTC hour is 07:00 or 09:00 local, never 08:00
    expect(localParts(Date.UTC(2026, 0, 15, 6, 0), TZ).hour).toBe(7);
    expect(localParts(Date.UTC(2026, 6, 15, 7, 0), TZ).hour).toBe(9);
  });

  it('local midnight is exact on both DST switch days', () => {
    expect(new Date(localMidnight(Date.UTC(2026, 2, 29, 10, 0), TZ)).toISOString()).toBe('2026-03-28T23:00:00.000Z');
    expect(new Date(localMidnight(Date.UTC(2026, 9, 25, 11, 0), TZ)).toISOString()).toBe('2026-10-24T22:00:00.000Z');
    expect(new Date(localMidnight(Date.UTC(2026, 6, 15, 6, 0), TZ)).toISOString()).toBe('2026-07-14T22:00:00.000Z');
  });

  it('every 5-minute tick of a day hits the 08:xx hour exactly 12 times, also on DST days', () => {
    for (const day of [Date.UTC(2026, 2, 29), Date.UTC(2026, 9, 25), Date.UTC(2026, 10, 3)]) {
      let hits = 0;
      for (let t = day - 6 * 3600_000; t < day + 30 * 3600_000; t += 300_000) {
        const p = localParts(t, TZ);
        if (p.hour === 8 && p.date === localParts(day + 12 * 3600_000, TZ).date) hits++;
      }
      expect(hits).toBe(12);
    }
  });

  it('ISO week keys, including the year boundary', () => {
    const key = (iso: string) => isoWeekKey(localParts(Date.parse(`${iso}T12:00:00Z`), TZ));
    expect(key('2026-11-02')).toBe('2026-W45');
    expect(key('2026-12-31')).toBe('2026-W53');
    expect(key('2027-01-01')).toBe('2026-W53');
    expect(key('2027-01-04')).toBe('2027-W01');
  });

  it('parses and formats durations', () => {
    expect(parseDuration('2h')).toBe(7_200_000);
    expect(parseDuration('30m')).toBe(1_800_000);
    expect(parseDuration('1d')).toBe(86_400_000);
    expect(parseDuration('90')).toBe(5_400_000);
    expect(parseDuration('1.5 hours')).toBe(5_400_000);
    expect(parseDuration('31d')).toBeNull();
    expect(parseDuration('soon')).toBeNull();
    expect(parseDuration(undefined)).toBeNull();
    expect(formatDuration(5_400_000)).toBe('1h 30m');
    expect(formatDuration(86_400_000)).toBe('1d');
  });
});

describe('mutes', () => {
  const now = Date.UTC(2026, 10, 3, 12);
  const m = (kind: Mute['kind'], value: string | null, until: number | null = now + 3600_000): Mute => ({ id: 1, kind, value, until });

  it('picks group, then vendor, then victim as the mute target', () => {
    expect(muteTarget({ attack_type: 'ransomware', group_name: 'Qilin', victim: 'Foo' })).toMatchObject({ kind: 'group', value: 'qilin' });
    expect(muteTarget({ attack_type: 'zero-day', vendor: 'Ivanti' })).toMatchObject({ kind: 'vendor', value: 'ivanti' });
    expect(muteTarget({ attack_type: 'zero-day', victim: 'Microsoft' })).toMatchObject({ kind: 'vendor', value: 'microsoft' });
    expect(muteTarget({ attack_type: 'breach', victim: 'Harvard University' })).toMatchObject({ kind: 'victim', value: 'harvard university' });
    expect(muteTarget({ attack_type: 'other' })).toBeNull();
  });

  it('targeted mutes silence, quiet time holds for the digest, expired mutes do nothing', () => {
    const qilin = { attack_type: 'ransomware', group_name: 'QILIN' };
    expect(muteStatus(qilin, [m('group', 'qilin')], now)).toBe('muted');
    expect(muteStatus(qilin, [m('group', 'akira')], now)).toBeNull();
    expect(muteStatus(qilin, [m('all', null)], now)).toBe('held');
    expect(muteStatus(qilin, [m('group', 'qilin', now - 1)], now)).toBeNull();
    expect(muteStatus({ attack_type: 'zero-day', victim: 'Microsoft' }, [m('vendor', 'microsoft')], now)).toBe('muted');
    // a vendor mute must not silence a *breach* whose victim is that company
    expect(muteStatus({ attack_type: 'breach', victim: 'Microsoft' }, [m('vendor', 'microsoft')], now)).toBeNull();
  });
});

const inc = (over: Partial<IncidentView> = {}): IncidentView => ({
  id: 42,
  title: 'Qilin claims attack on Acme <Ltd>',
  summary: 's',
  url: 'https://x.test/a?b=1&c=2',
  attack_type: 'ransomware',
  sector: 'Healthcare',
  country: 'DE',
  severity: 3,
  source_count: 2,
  sources: null,
  group_name: 'Qilin',
  ...over,
});

describe('alert keyboard + lists', () => {
  it('has More info and a labelled Mute button with short callback data', () => {
    const kb = alertKeyboard(inc());
    expect(kb.inline_keyboard[0]!.map((b) => b.callback_data)).toEqual(['info:42', 'mute:42']);
    expect(kb.inline_keyboard[0]![1]!.text).toContain('Qilin');
    for (const b of kb.inline_keyboard[0]!) expect(new TextEncoder().encode(b.callback_data).length).toBeLessThanOrEqual(64);
    expect(alertKeyboard(inc({ group_name: null, attack_type: 'other', victim: null })).inline_keyboard[0]).toHaveLength(1);
  });

  it('formats one escaped, linked line per incident', () => {
    expect(formatIncidentLine(inc())).toBe('🟡 🔒 <a href="https://x.test/a?b=1&amp;c=2">Qilin claims attack on Acme &lt;Ltd&gt;</a> 🇩🇪 · 2 src');
  });

  it('splits long text on line boundaries under the limit', () => {
    const text = Array.from({ length: 200 }, (_, i) => `line ${i} ${'x'.repeat(40)}`).join('\n');
    const parts = splitMessage(text, 1000);
    expect(parts.length).toBeGreaterThan(5);
    for (const p of parts) expect(p.length).toBeLessThanOrEqual(1000);
    expect(parts.join('\n')).toBe(text);
  });

  it('formats trends', () => {
    expect(trend(15, 10)).toBe('▲50%');
    expect(trend(5, 10)).toBe('▼50%');
    expect(trend(3, 0)).toBe('🆕');
    expect(trend(4, 4)).toBe('＝');
  });

  it('formats the digest, including the quiet case', () => {
    expect(formatDigest({ dateLabel: 'Tue 4 Nov', incidents: [], total: 0 })).toContain('Quiet 24 hours');
    const d = formatDigest({ dateLabel: 'Tue 4 Nov', incidents: [inc(), inc({ id: 2, attack_type: 'breach' })], total: 5 });
    expect(d).toContain('5 incidents below your alert threshold');
    expect(d).toContain('🔒 1');
    expect(d).toContain('…and 3 more');
  });

  it('formats the weekly report with trends and flags', () => {
    const w = formatWeekly({
      rangeLabel: 'Tue 28 Oct – Mon 3 Nov',
      total: { key: 'all', cur: 120, prev: 100 },
      bySeverity: [{ severity: 4, n: 10 }, { severity: 3, n: 110 }],
      byType: [{ key: 'ransomware', cur: 80, prev: 70 }],
      groups: [{ key: 'Qilin', cur: 12, prev: 6 }],
      sectors: [{ key: 'Healthcare', cur: 9, prev: 9 }],
      countries: [{ key: 'US', cur: 50, prev: 0 }],
      top: [inc({ severity: 5 })],
    });
    expect(w).toContain('<b>120</b> incidents (previous 7 days: 100) ▲20%');
    expect(w).toContain('1. 👾 Qilin — <b>12</b> ▲100%');
    expect(w).toContain('🇺🇸 US — <b>50</b> 🆕');
    expect(w).toContain('Healthcare — <b>9</b> ＝');
    expect(w).toContain('<b>Top incidents</b>\n🔴');
  });
});

describe('webhook helpers', () => {
  it('parses commands with bot suffix and arguments', () => {
    expect(parseCommand('/mute@CyberAlertBot 2h')).toEqual({ cmd: '/mute', arg: '2h' });
    expect(parseCommand('/latest')).toEqual({ cmd: '/latest', arg: undefined });
    expect(parseCommand('  /UNMUTE  qilin ')).toEqual({ cmd: '/unmute', arg: 'qilin' });
  });

  it('only accepts the owner, for callbacks too', () => {
    const env = { TELEGRAM_CHAT_ID: '123456789' } as Env;
    expect(isOwner(env, 123456789)).toBe(true);
    expect(isOwner(env, 123)).toBe(false);
  });
});
