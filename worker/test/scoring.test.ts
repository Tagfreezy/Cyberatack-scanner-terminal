import { describe, expect, it } from 'vitest';
import { scoreItem } from '../src/scoring';
import { parseNewsFeed } from '../src/sources/news';
import { fixture, newsItem } from './helpers';

describe('keyword scoring', () => {
  it('flags ransomware attacks on hospitals as high', () => {
    const s = scoreItem(newsItem('Ransomware attack disrupts hospital network across three states'));
    expect(s).toMatchObject({ isIncident: true, attackType: 'ransomware', severity: 4 });
  });

  it('detects exploited zero-days', () => {
    const s = scoreItem(newsItem('Chrome zero-day actively exploited in attacks, patch now'));
    expect(s.isIncident).toBe(true);
    expect(s.attackType).toBe('zero-day');
    expect(s.severity).toBeGreaterThanOrEqual(3);
  });

  it('detects breaches and boosts large scale', () => {
    const s = scoreItem(newsItem('Retailer data breach exposes 12 million customer records'));
    expect(s).toMatchObject({ isIncident: true, attackType: 'breach' });
    expect(s.reasons).toContain('large-scale');
  });

  it('never goes above 4 from keywords alone (5 is reserved for AI)', () => {
    const s = scoreItem(newsItem('Ransomware hits hospital chain, millions of patients affected nationwide'));
    expect(s.severity).toBe(4);
  });

  it.each([
    'Webinar: How to build a modern SOC',
    'The best VPN deals this week',
    'Acme raises $50 million to fight ransomware',
    'Gartner predicts SOCs will have 50% more engineers',
    'Weekly recap: patch tuesday and more',
  ])('filters noise: %s', (title) => {
    expect(scoreItem(newsItem(title)).isIncident).toBe(false);
  });

  it('keeps noise words if a strong signal is in the title', () => {
    expect(scoreItem(newsItem('Company announces data breach after ransomware attack')).isIncident).toBe(true);
  });

  it('filters sponsored posts by author', () => {
    const item = newsItem('Ransomware readiness checklist', '', { meta: { author: 'Sponsored by Acme' } });
    expect(scoreItem(item).isIncident).toBe(false);
  });

  it('does not treat a plain patch notice as an incident', () => {
    expect(scoreItem(newsItem('Barracuda warns of critical flaws allowing root access to devices')).isIncident).toBe(false);
    expect(scoreItem(newsItem('Langflow flaw could be exploited to run code on servers')).isIncident).toBe(false);
  });

  // Real headlines from 2026-11-03 that an early version missed.
  it.each([
    ['Fintech platform Sageworks taken offline after suspected cyberattack', 'other'],
    ['Hackers disrupt refrigeration systems at European supermarkets', 'other'],
    ['Hackers Exploit BTCPay Server Flaw to Steal Bitcoin and Litecoin From Hot Wallets', 'zero-day'],
    ['Over 1,000 GitLab servers vulnerable to ongoing RCE attacks', 'zero-day'],
    ['cPGuard Update Channel Hijacked to Backdoor Linux Servers', 'supply-chain'],
    ['Florida Student Aid Website Hack Puts Data of 4.9 Million People at Risk', 'breach'],
  ])('catches: %s', (title, type) => {
    expect(scoreItem(newsItem(title))).toMatchObject({ isIncident: true, attackType: type });
  });

  it('takes the attack type from the headline over the summary', () => {
    const s = scoreItem(newsItem('Frontline Education data breach impacts over 1.3 million', 'Attackers exploited a flaw.'));
    expect(s.attackType).toBe('breach');
  });

  it('needs a signal in the headline, not just the summary', () => {
    const s = scoreItem(newsItem('Your mobile carrier stores call logs for years', 'Attackers could steal them in a breach.'));
    expect(s.isIncident).toBe(false);
  });

  it('scores KEV entries, higher with known ransomware use', () => {
    const base = newsItem('CVE-2026-1: X', '', { typeHint: 'kev', meta: { knownRansomware: false } });
    expect(scoreItem(base)).toMatchObject({ isIncident: true, attackType: 'zero-day', severity: 3 });
    expect(scoreItem({ ...base, meta: { knownRansomware: true } }).severity).toBe(4);
  });

  it('scores leak-site posts as ransomware, digest-level by default', () => {
    const leak = newsItem('Qilin claims attack on Foo', 'Foo makes widgets.', { typeHint: 'leak', meta: { group: 'Qilin' } });
    expect(scoreItem(leak)).toMatchObject({ isIncident: true, attackType: 'ransomware', severity: 3 });
    expect(scoreItem({ ...leak, summary: 'Regional hospital in Ohio.' }).severity).toBe(4);
  });

  it('on a real feed, filters some items and keeps some', () => {
    const items = parseNewsFeed('thehackernews', fixture('thehackernews.xml'), 20);
    const scores = items.map(scoreItem);
    expect(scores.some((s) => s.isIncident)).toBe(true);
    expect(scores.some((s) => !s.isIncident)).toBe(true);
  });
});
