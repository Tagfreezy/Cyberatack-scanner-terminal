import { describe, expect, it } from 'vitest';
import { validateClassification, type Classification } from '../src/ai';
import { cosine, extractCve, findMatch, victimKey, victimKeysMatch, type Candidate } from '../src/dedupe';
import { blobToVector, decide } from '../src/process';
import { newsItem } from './helpers';

const good = {
  is_incident: true,
  attack_type: 'ransomware',
  victim: 'Acme Corp',
  sector: 'Healthcare',
  country: 'us',
  severity: 4,
  summary: 'Ransomware gang encrypted Acme hospital systems, forcing ambulance diversions.',
};

describe('AI output validation', () => {
  it('accepts a clean object and normalises fields', () => {
    expect(validateClassification(good)).toMatchObject({ attack_type: 'ransomware', country: 'US', severity: 4, sector: 'Healthcare' });
  });

  it('extracts JSON from prose and ```json fences', () => {
    const s = 'Sure! Here is the result:\n```json\n' + JSON.stringify(good) + '\n```';
    expect(validateClassification(s)?.victim).toBe('Acme Corp');
  });

  it('rejects garbage and missing required fields (→ retry / keyword fallback)', () => {
    expect(validateClassification('no json here')).toBeNull();
    expect(validateClassification('{"is_incident": true, "summary": "x"')).toBeNull(); // truncated
    expect(validateClassification({ ...good, is_incident: undefined })).toBeNull();
    expect(validateClassification({ ...good, severity: 'high' })).toBeNull();
    expect(validateClassification({ ...good, summary: '' })).toBeNull();
    expect(validateClassification(null)).toBeNull();
  });

  it('clamps and maps out-of-range values instead of failing', () => {
    const c = validateClassification({ ...good, severity: 9, attack_type: 'Zero Day', country: 'UK', sector: 'hospitals', victim: 'Unknown' })!;
    expect(c).toMatchObject({ severity: 5, attack_type: 'zero-day', country: 'GB', sector: 'Other', victim: null });
    expect(validateClassification({ ...good, attack_type: 'phishing', country: 'Europe' })).toMatchObject({ attack_type: 'other', country: null });
  });

  it('accepts a non-incident with an empty summary', () => {
    expect(validateClassification({ ...good, is_incident: false, summary: '' })?.is_incident).toBe(false);
  });
});

describe('victim keys', () => {
  it.each([
    ['marlo-inc.com', 'marlo'],
    ['Marlo Incorporated', 'marlo'], // leak-site domain and AI-extracted name meet
    ['https://www.acme.co.uk/', 'acme'],
    ['Acme Holdings, Inc.', 'acme'],
    ['MARDEC Berhad', 'mardec'],
    ['Harvard University', 'harvard university'],
    ['City of Edgewater', 'city of edgewater'],
  ])('%s → %s', (input, out) => expect(victimKey(input)).toBe(out));

  it('ignores generic / too short names', () => {
    expect(victimKey('Unknown')).toBeNull();
    expect(victimKey('Hospital')).toBeNull();
    expect(victimKey('AB')).toBeNull();
    expect(victimKey(null)).toBeNull();
  });

  it('matches equal keys and word prefixes, not substrings', () => {
    expect(victimKeysMatch('harvard', 'harvard university')).toBe(true);
    expect(victimKeysMatch('acme', 'acme')).toBe(true);
    expect(victimKeysMatch('acme', 'acme labs')).toBe(false); // "acme" is < 5 chars: too risky
    expect(victimKeysMatch('harvard', 'harvardx')).toBe(false);
    expect(victimKeysMatch(null, 'x')).toBe(false);
  });
});

describe('dedupe matching', () => {
  const now = Date.UTC(2026, 10, 3, 12);
  const cands: Candidate[] = [
    { id: 1, victim_key: 'harvard university', cve: null, first_seen: now - 3600_000 },
    { id: 2, victim_key: null, cve: 'CVE-2026-1234', first_seen: now - 7200_000 },
    { id: 3, victim_key: 'old victim', cve: null, first_seen: now - 80 * 3600_000 }, // outside 72h
    { id: 4, victim_key: null, cve: null, first_seen: now - 600_000 },
  ];

  it('prefers CVE, then victim, then vectors', () => {
    expect(findMatch({ victimKey: 'harvard', cve: 'CVE-2026-1234' }, cands, [], 0.7, now)).toMatchObject({ id: 2, reason: 'cve' });
    expect(findMatch({ victimKey: 'harvard', cve: null }, cands, [], 0.7, now)).toMatchObject({ id: 1, reason: 'victim' });
    expect(findMatch({ victimKey: null, cve: null }, cands, [{ id: 4, score: 0.81 }, { id: 1, score: 0.75 }], 0.7, now)).toMatchObject({
      id: 4,
      reason: 'vector',
    });
  });

  it('ignores vectors below the threshold and incidents outside the 72h window', () => {
    expect(findMatch({ victimKey: null, cve: null }, cands, [{ id: 4, score: 0.65 }], 0.7, now)).toBeNull();
    expect(findMatch({ victimKey: 'old victim', cve: null }, cands, [{ id: 3, score: 0.99 }], 0.7, now)).toBeNull();
  });

  it('finds CVE ids in text', () => {
    expect(extractCve('Attackers exploit cve-2026-118527 in Ivanti')).toBe('CVE-2026-118527');
    expect(extractCve('no id here')).toBeNull();
  });

  it('computes cosine similarity', () => {
    expect(cosine([1, 0], [1, 0])).toBeCloseTo(1);
    expect(cosine([1, 0], [0, 1])).toBeCloseTo(0);
    expect(cosine([0, 0], [1, 1])).toBe(0);
  });
});

describe('decide (AI + source data + fallback)', () => {
  const ai: Classification = { ...(validateClassification(good) as Classification) };

  it('uses keyword scoring when AI is unavailable (never drops items)', () => {
    const d = decide(newsItem('Ransomware attack disrupts hospital network'), null);
    expect(d).toMatchObject({ isIncident: true, classifiedBy: 'keywords', severity: 4 });
  });

  it('trusts the AI for news, including "not an incident"', () => {
    expect(decide(newsItem('Something'), ai)).toMatchObject({ isIncident: true, severity: 4, classifiedBy: 'ai', victim: 'Acme Corp' });
    expect(decide(newsItem('Ransomware report says...'), { ...ai, is_incident: false })).toMatchObject({ isIncident: false, severity: 1 });
  });

  it('for leak posts: always ransomware, source victim/country win, keyword severity, AI sector', () => {
    const leak = newsItem('Qilin claims attack on Foo', 'Foo makes widgets.', {
      typeHint: 'leak',
      meta: { group: 'Qilin', victim: 'foo.com', country: 'DE' },
    });
    const d = decide(leak, { ...ai, severity: 5, attack_type: 'breach', country: 'US', victim: 'Foo GmbH', sector: 'Manufacturing' });
    expect(d).toMatchObject({ isIncident: true, attackType: 'ransomware', severity: 3, victim: 'foo.com', country: 'DE', sector: 'Manufacturing', classifiedBy: 'ai' });
  });
});

describe('vector blobs', () => {
  it("round-trips a Float32 vector through D1's byte-array BLOB format", () => {
    const v = new Float32Array([0.5, -1.25, 3e-7, 42]);
    const asD1Returns = Array.from(new Uint8Array(v.buffer)); // D1 reads BLOBs back as number[]
    expect(Array.from(blobToVector(asD1Returns))).toEqual(Array.from(v));
  });
});
