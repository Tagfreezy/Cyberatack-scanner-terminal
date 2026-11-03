import { describe, expect, it } from 'vitest';
import { dueSources } from '../src/scheduler';
import { countryFlag, escapeAttr, escapeHtml, formatAlert, type IncidentView } from '../src/telegram/format';
import { isOwner } from '../src/telegram/webhook';
import type { Env } from '../src/types';

const inc = (over: Partial<IncidentView> = {}): IncidentView => ({
  id: 1,
  title: 'Qilin claims attack on Acme & Sons <Ltd>',
  summary: 'Data of 5 < 6 employees leaked',
  url: 'https://example.com/a?b=1&c="2"',
  attack_type: 'ransomware',
  sector: 'Manufacturing',
  country: 'ch',
  severity: 4,
  source_count: 2,
  sources: JSON.stringify(['bleepingcomputer', 'ransomware.live']),
  group_name: 'Qilin',
  ...over,
});

describe('telegram formatting', () => {
  it('escapes HTML special chars', () => {
    expect(escapeHtml('a & <b> "c"')).toBe('a &amp; &lt;b&gt; "c"');
    expect(escapeAttr('a&"b')).toBe('a&amp;&quot;b');
  });

  it('builds flags from ISO codes', () => {
    expect(countryFlag('CH')).toBe('🇨🇭');
    expect(countryFlag('us')).toBe('🇺🇸');
    expect(countryFlag('UK')).toBe('🇬🇧');
    expect(countryFlag('XYZ')).toBe('');
    expect(countryFlag(null)).toBe('');
  });

  it('formats an alert with all parts, escaped', () => {
    const t = formatAlert(inc());
    expect(t).toContain('🟠 <b>HIGH</b> · Ransomware');
    expect(t).toContain('<b>Qilin claims attack on Acme &amp; Sons &lt;Ltd&gt;</b>');
    expect(t).toContain('Data of 5 &lt; 6 employees leaked');
    expect(t).toContain('🇨🇭 CH');
    expect(t).toContain('📰 2 sources (BleepingComputer, ransomware.live)');
    expect(t).toContain('<a href="https://example.com/a?b=1&amp;c=&quot;2&quot;">Read more</a>');
    // nothing unescaped slipped through: only our own tags remain
    expect(t.replace(/<\/?b>|<a href="[^"]*">|<\/a>/g, '')).not.toMatch(/[<>]/);
  });

  it('uses the right badge per severity', () => {
    expect(formatAlert(inc({ severity: 5 }))).toMatch(/^🔴 <b>CRITICAL<\/b>/);
    expect(formatAlert(inc({ severity: 3 }))).toMatch(/^🟡 <b>MEDIUM<\/b>/);
  });

  it('handles missing optional fields and singular source', () => {
    const t = formatAlert(inc({ summary: null, url: null, sector: null, country: null, group_name: null, source_count: 1, sources: null }));
    expect(t).toContain('📰 1 source');
    expect(t).not.toContain('Read more');
  });

  it('stays under the Telegram 4096 char limit', () => {
    expect(formatAlert(inc({ title: 'x'.repeat(5000), summary: 'y'.repeat(5000) })).length).toBeLessThan(1500);
  });

  it('only answers the owner chat', () => {
    const env = { TELEGRAM_CHAT_ID: '12345' } as Env;
    expect(isOwner(env, 12345)).toBe(true);
    expect(isOwner(env, 99999)).toBe(false);
    expect(isOwner(env, undefined)).toBe(false);
  });
});

describe('scheduler', () => {
  it('spreads sources over the hour', () => {
    const counts: Record<string, number> = {};
    for (let m = 0; m < 60; m += 5) {
      for (const s of dueSources(Date.UTC(2026, 10, 3, 12, m))) counts[s.name] = (counts[s.name] ?? 0) + 1;
    }
    expect(counts).toEqual({
      bleepingcomputer: 3,
      therecord: 3,
      thehackernews: 3,
      securityweek: 3,
      'ransomware.live': 4,
      'cisa-kev': 1,
    });
  });

  it('never runs more than 3 sources in one tick', () => {
    for (let m = 0; m < 60; m += 5) expect(dueSources(Date.UTC(2026, 10, 3, 12, m)).length).toBeLessThanOrEqual(3);
  });
});
