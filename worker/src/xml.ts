// Minimal RSS/Atom scanner. A full DOM parser (e.g. fast-xml-parser) can blow the free
// plan's 10 ms CPU budget on big feeds, so we only slice out the first N <item>/<entry>
// blocks with indexOf and read a handful of tags from each.

export interface RawFeedEntry {
  title: string;
  link: string;
  guid: string;
  pubDate: string;
  description: string;
  categories: string[];
  creator: string;
}

const NAMED_ENTITIES: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: ' ',
  hellip: '…',
  mdash: '—',
  ndash: '–',
  rsquo: '’',
  lsquo: '‘',
  rdquo: '”',
  ldquo: '“',
};

export function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e: string) => {
    if (e[0] === '#') {
      const code = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(code) && code > 0 && code < 0x110000 ? String.fromCodePoint(code) : m;
    }
    return NAMED_ENTITIES[e.toLowerCase()] ?? m;
  });
}

/** Text content of a tag value: unwrap CDATA, decode entities (outside CDATA). */
function textValue(raw: string): string {
  let out = '';
  let i = 0;
  while (i < raw.length) {
    const start = raw.indexOf('<![CDATA[', i);
    if (start === -1) {
      out += decodeEntities(raw.slice(i));
      break;
    }
    out += decodeEntities(raw.slice(i, start));
    const end = raw.indexOf(']]>', start + 9);
    if (end === -1) {
      out += raw.slice(start + 9);
      break;
    }
    out += raw.slice(start + 9, end);
    i = end + 3;
  }
  return out.trim();
}

export function stripHtml(s: string): string {
  return decodeEntities(s.replace(/<[^>]*>/g, ' ')).replace(/\s+/g, ' ').trim();
}

/** All occurrences of <tag ...>value</tag> (or self-closing) within block. */
function findTags(block: string, tag: string): { attrs: string; value: string }[] {
  const res: { attrs: string; value: string }[] = [];
  const open = `<${tag}`;
  let i = 0;
  for (;;) {
    const s = block.indexOf(open, i);
    if (s === -1) break;
    const after = block.charCodeAt(s + open.length);
    // must be followed by '>', '/', or whitespace (so <link> doesn't match <linkedin>)
    if (!(after === 62 || after === 47 || after === 32 || after === 9 || after === 10 || after === 13)) {
      i = s + open.length;
      continue;
    }
    const gt = block.indexOf('>', s);
    if (gt === -1) break;
    const attrs = block.slice(s + open.length, gt);
    if (attrs.endsWith('/')) {
      res.push({ attrs, value: '' });
      i = gt + 1;
      continue;
    }
    const close = block.indexOf(`</${tag}>`, gt);
    if (close === -1) break;
    res.push({ attrs, value: block.slice(gt + 1, close) });
    i = close + tag.length + 3;
  }
  return res;
}

function first(block: string, ...tags: string[]): string {
  for (const t of tags) {
    const f = findTags(block, t)[0];
    if (f && f.value) return textValue(f.value);
  }
  return '';
}

function attr(attrs: string, name: string): string | null {
  const m = attrs.match(new RegExp(`\\b${name}\\s*=\\s*("([^"]*)"|'([^']*)')`));
  return m ? decodeEntities(m[2] ?? m[3] ?? '') : null;
}

/** Parse the first `max` items of an RSS 2.0 or Atom feed. */
export function parseFeed(xml: string, max = 20): RawFeedEntry[] {
  const isAtom = xml.indexOf('<item') === -1 && xml.indexOf('<entry') !== -1;
  const tag = isAtom ? 'entry' : 'item';
  const out: RawFeedEntry[] = [];
  let i = 0;
  while (out.length < max) {
    let s = xml.indexOf(`<${tag}`, i);
    if (s === -1) break;
    const c = xml.charCodeAt(s + tag.length + 1);
    if (c !== 62 && c !== 32 && c !== 10 && c !== 13 && c !== 9) {
      i = s + 1;
      continue;
    }
    const e = xml.indexOf(`</${tag}>`, s);
    if (e === -1) break;
    const block = xml.slice(s, e);
    i = e + tag.length + 3;

    let link = '';
    if (isAtom) {
      const links = findTags(block, 'link');
      const alt = links.find((l) => (attr(l.attrs, 'rel') ?? 'alternate') === 'alternate') ?? links[0];
      link = alt ? (attr(alt.attrs, 'href') ?? textValue(alt.value)) : '';
    } else {
      link = first(block, 'link');
    }

    out.push({
      title: stripHtml(first(block, 'title')),
      link: link.trim(),
      guid: first(block, 'guid', 'id') || link.trim(),
      pubDate: first(block, 'pubDate', 'published', 'updated', 'dc:date'),
      description: stripHtml(first(block, 'description', 'summary', 'content:encoded', 'content')),
      categories: findTags(block, 'category')
        .map((c) => textValue(c.value) || attr(c.attrs, 'term') || '')
        .filter(Boolean),
      creator: first(block, 'dc:creator', 'author'),
    });
    s = i;
  }
  return out;
}

export function parseDate(s: string): number | null {
  if (!s) return null;
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : null;
}
