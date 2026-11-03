import { describe, expect, it } from 'vitest';
import { parseKevHead, kevToItem } from '../src/sources/kev';
import { NEWS_FEEDS, parseNewsFeed } from '../src/sources/news';
import { parseRansomwareLiveRss, proVictimToItem } from '../src/sources/ransomwarelive';
import { readFeedHead } from '../src/http';
import { decodeEntities, parseFeed } from '../src/xml';
import { fixture } from './helpers';

describe('xml scanner', () => {
  it('decodes named and numeric entities', () => {
    expect(decodeEntities('A &amp; B &lt;x&gt; &#8217; &#x2014; &quot;q&quot;')).toBe('A & B <x> ’ — "q"');
  });

  it('unwraps CDATA and does not decode entities inside it', () => {
    const xml = '<rss><channel><item><title><![CDATA[Tom &amp; Jerry]]></title><link>https://x.test/1</link></item></channel></rss>';
    expect(parseFeed(xml)[0]!.title).toBe('Tom & Jerry'); // stripHtml decodes once after
  });

  it('parses Atom feeds', () => {
    const xml = `<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
      <entry><title>Atom title</title><link rel="alternate" href="https://a.test/post"/>
      <id>tag:a.test,1</id><published>2026-11-03T10:00:00Z</published><summary>&lt;p&gt;Hi&lt;/p&gt;</summary></entry>
      </feed>`;
    const [e] = parseFeed(xml);
    expect(e).toMatchObject({ title: 'Atom title', link: 'https://a.test/post', guid: 'tag:a.test,1', description: 'Hi' });
  });

  it('respects the max-items cap', () => {
    expect(parseFeed(fixture('thehackernews.xml'), 3)).toHaveLength(3);
  });
});

describe('news feeds (real fixtures)', () => {
  const files: Record<string, string> = {
    darkreading: 'darkreading.xml',
    therecord: 'therecord.xml',
    thehackernews: 'thehackernews.xml',
    securityweek: 'securityweek.xml',
  };
  for (const f of NEWS_FEEDS) {
    it(`parses ${f.name}`, () => {
      const items = parseNewsFeed(f.name, fixture(files[f.name]!), 20);
      expect(items.length).toBeGreaterThan(3);
      expect(items.length).toBeLessThanOrEqual(20);
      for (const it of items) {
        expect(it.title.length).toBeGreaterThan(5);
        expect(it.title).not.toMatch(/CDATA|<\/?[a-z]+>/i);
        expect(it.url).toMatch(/^https?:\/\//);
        expect(it.publishedAt).toBeGreaterThan(Date.parse('2020-01-01'));
        expect(it.id).toMatch(new RegExp(`^${f.name}:[0-9a-f]{8}$`));
      }
      // ids are unique and stable
      expect(new Set(items.map((i) => i.id)).size).toBe(items.length);
      expect(parseNewsFeed(f.name, fixture(files[f.name]!), 20).map((i) => i.id)).toEqual(items.map((i) => i.id));
    });
  }

  it('keeps the dc:creator so sponsored posts can be filtered', () => {
    const items = parseNewsFeed('bleepingcomputer', fixture('bleepingcomputer.xml'), 20);
    expect(items.some((i) => /sponsored/i.test(i.meta.author ?? ''))).toBe(true);
  });
});

describe('CISA KEV head parser', () => {
  it('reads header + complete objects from a truncated prefix', () => {
    const head = parseKevHead(fixture('kev_head.json'), 30);
    expect(head.count).toBe(1766);
    expect(head.dateReleased).toBe('2026-10-30T17:02:45.3665Z');
    expect(head.vulns.length).toBeGreaterThan(10);
    expect(head.vulns[0]!.cveID).toBe('CVE-2026-118527');
    for (const v of head.vulns) expect(v.cveID).toMatch(/^CVE-\d{4}-\d+$/);
  });

  it('handles braces and escaped quotes inside strings, and stops at a cut-off object', () => {
    const text =
      '{"count": 2, "dateReleased": "x", "vulnerabilities": [ {"cveID":"CVE-1-1","shortDescription":"a } \\" { b"}, {"cveID":"CVE-1-2","short';
    const head = parseKevHead(text);
    expect(head.vulns).toHaveLength(1);
    expect(head.vulns[0]!.shortDescription).toBe('a } " { b');
  });

  it('maps an entry to an item', () => {
    const item = kevToItem({
      cveID: 'CVE-2026-1',
      vendorProject: 'Acme',
      product: 'Gateway',
      vulnerabilityName: 'Acme Gateway RCE',
      dateAdded: '2026-10-30',
      shortDescription: 'desc',
      knownRansomwareCampaignUse: 'Known',
    });
    expect(item).toMatchObject({ id: 'kev:CVE-2026-1', typeHint: 'kev', meta: { vendor: 'Acme', knownRansomware: true } });
  });
});

describe('ransomware.live', () => {
  it('parses victim, group and country from the RSS feed', () => {
    const items = parseRansomwareLiveRss(fixture('ransomwarelive.xml'), 40);
    expect(items.length).toBe(30);
    const first = items[0]!;
    expect(first.meta).toMatchObject({ group: 'Settra', victim: 'marlo-inc.com', country: 'US' });
    expect(first.title).toBe('Settra claims attack on marlo-inc.com');
    expect(first.id).toBe('rl:bWFybG8taW5jLmNvbUBzZXR0cmE');
    expect(items.every((i) => i.meta.group && i.meta.victim)).toBe(true);
    // "N/A" descriptions are dropped
    expect(items.some((i) => i.summary === 'N/A')).toBe(false);
  });

  it('maps PRO API victims to the same id scheme', () => {
    const item = proVictimToItem({
      id: 'bWFybG8taW5jLmNvbUBzZXR0cmE',
      victim: 'marlo-inc.com',
      group: 'settra',
      country: 'us',
      activity: 'Manufacturing',
      discovered: '2026-11-03 17:17:32',
    });
    expect(item).toMatchObject({ id: 'rl:bWFybG8taW5jLmNvbUBzZXR0cmE', meta: { country: 'US', sector: 'Manufacturing' } });
  });
});

describe('readFeedHead (streamed, cancels early)', () => {
  function chunked(text: string, size: number): Response {
    const bytes = new TextEncoder().encode(text);
    let pulled = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(ctrl) {
        if (pulled >= bytes.length) return ctrl.close();
        ctrl.enqueue(bytes.slice(pulled, pulled + size));
        pulled += size;
      },
    });
    return new Response(stream);
  }

  it('stops after N items, even with tags split across chunks', async () => {
    const xml = fixture('ransomwarelive.xml'); // 30 items
    for (const size of [7, 100, 4096]) {
      const head = await readFeedHead(chunked(xml, size), 10);
      const items = parseRansomwareLiveRss(head, 40);
      expect(items.length).toBeGreaterThanOrEqual(10);
      expect(items.length).toBeLessThan(30);
      expect(items[0]!.meta.victim).toBe('marlo-inc.com');
    }
  });

  it('returns the whole body when it has fewer items than asked', async () => {
    const xml = fixture('therecord.xml'); // 5 items
    expect(parseNewsFeed('therecord', await readFeedHead(chunked(xml, 512), 20), 20)).toHaveLength(5);
  });
});
