import { log, logError } from './log';
import type { AttackType, Env, Item } from './types';

// Workers AI: classification (small instruct model, strict JSON) + embeddings for dedupe.
// Free plan = 10,000 neurons/day. One classification ≈ 600 input + 120 output tokens,
// i.e. well under 10 neurons on the models we use, so ~150 items/day costs ~1,500 neurons.

export const ATTACK_TYPES: AttackType[] = ['ransomware', 'breach', 'ddos', 'zero-day', 'supply-chain', 'wiper', 'other'];

// Fixed sector list so stats group cleanly ("Healthcare" not "hospital"/"health care"/...).
export const SECTORS = [
  'Healthcare',
  'Government',
  'Education',
  'Finance',
  'Technology',
  'Manufacturing',
  'Retail',
  'Energy & Utilities',
  'Transportation',
  'Telecommunications',
  'Professional Services',
  'Media',
  'Hospitality',
  'Construction & Real Estate',
  'Agriculture & Food',
  'Defense',
  'Non-profit',
  'Crypto',
  'Other',
] as const;

export interface Classification {
  is_incident: boolean;
  attack_type: AttackType;
  victim: string | null;
  sector: string | null;
  country: string | null; // ISO-2
  severity: number; // 1-5
  summary: string;
}

const SYSTEM_PROMPT = `You are a cyber threat intelligence analyst. You read one cybersecurity news item and return ONLY a JSON object, no prose, no markdown.

Decide if it reports a REAL cyberattack or actively exploited vulnerability that already happened (is_incident=true). An outage or shutdown blamed on a "suspected" cyberattack counts as an incident.
NOT incidents (is_incident=false): patch notices without exploitation, research, forecasts, opinion, product news, funding, how-to articles, and law-enforcement or vendor actions AGAINST attackers (arrests, takedowns, seized servers, botnet disruptions).

JSON keys:
- is_incident: boolean
- attack_type: one of "ransomware","breach","ddos","zero-day","supply-chain","wiper","other" ("zero-day" also covers any actively exploited vulnerability)
- victim: main victim organisation name, or the affected vendor/product for exploited vulnerabilities, or null
- sector: one of ${SECTORS.map((s) => `"${s}"`).join(',')}, or null
- country: ISO 3166-1 alpha-2 code of the victim's country, or null if unknown or global
- severity: integer 1-5
    5 = critical: national-scale disruption, critical infrastructure down, >10 million people affected, mass exploitation of a very widely used product
    4 = high: hospital/government/large company with operational impact, >100,000 people affected, actively exploited flaw in common enterprise products
    3 = medium: confirmed attack on a mid-size organisation, smaller breaches, typical ransomware leak-site claims
    2 = low: small organisations, unconfirmed or minor incidents
    1 = informational / not an incident
- summary: ONE plain-English sentence (max 30 words) saying what happened, to whom, and the impact`;

function userPrompt(item: Item): string {
  if (item.typeHint === 'leak') {
    return [
      `Source: ransomware gang leak site (a claim by the gang "${item.meta.group ?? 'unknown'}", treat as is_incident=true, attack_type="ransomware").`,
      `Victim: ${item.meta.victim ?? item.title}`,
      item.meta.country ? `Country: ${item.meta.country}` : '',
      `Description: ${item.summary || 'none'}`,
    ]
      .filter(Boolean)
      .join('\n');
  }
  return `Source: ${item.source} (news)\nTitle: ${item.title}\nSummary: ${item.summary.slice(0, 700)}`;
}

/** Validate + normalise model output. Returns null if it isn't usable. */
export function validateClassification(raw: unknown): Classification | null {
  let obj: unknown = raw;
  if (typeof obj === 'string') {
    // Models sometimes wrap JSON in prose or ```json fences: take the outermost {...}.
    const s = obj.indexOf('{');
    const e = obj.lastIndexOf('}');
    if (s === -1 || e <= s) return null;
    try {
      obj = JSON.parse(obj.slice(s, e + 1));
    } catch {
      return null;
    }
  }
  if (!obj || typeof obj !== 'object') return null;
  const o = obj as Record<string, unknown>;

  const isIncident = o.is_incident === true || o.is_incident === 'true';
  if (o.is_incident === undefined) return null;

  const type = String(o.attack_type ?? '').toLowerCase().trim().replace(/\s+/g, '-');
  const attack_type = (ATTACK_TYPES as string[]).includes(type) ? (type as AttackType) : 'other';

  const sevNum = Math.round(Number(o.severity));
  if (!Number.isFinite(sevNum)) return null;
  const severity = Math.max(1, Math.min(5, sevNum));

  const summary = typeof o.summary === 'string' ? o.summary.trim().replace(/\s+/g, ' ').slice(0, 280) : '';
  if (isIncident && summary.length < 10) return null;

  const victimRaw = typeof o.victim === 'string' ? o.victim.trim() : '';
  const victim = victimRaw && !/^(null|none|unknown|n\/?a|various|multiple|undisclosed)$/i.test(victimRaw) ? victimRaw.slice(0, 120) : null;

  const sectorRaw = typeof o.sector === 'string' ? o.sector.trim().toLowerCase() : '';
  const sector = SECTORS.find((s) => s.toLowerCase() === sectorRaw) ?? (sectorRaw && sectorRaw !== 'null' ? 'Other' : null);

  const c = typeof o.country === 'string' ? o.country.trim().toUpperCase() : '';
  const country = /^[A-Z]{2}$/.test(c) ? (c === 'UK' ? 'GB' : c) : null;

  return { is_incident: isIncident, attack_type, victim, sector, country, severity, summary };
}

/**
 * AI is unavailable for a while: the caller pauses AI until `until` and uses keyword
 * fallback meanwhile. Daily quota → until next UTC midnight; rate limits → 15 minutes.
 */
export class AiQuotaError extends Error {
  constructor(
    message: string,
    public until: number,
  ) {
    super(message);
  }
}

function quotaPause(err: unknown, now = Date.now()): AiQuotaError | null {
  const m = err instanceof Error ? err.message : String(err);
  if (/4006|daily free allocation|neurons/i.test(m)) {
    const midnight = new Date(now);
    midnight.setUTCHours(24, 0, 0, 0);
    return new AiQuotaError(m, midnight.getTime());
  }
  if (/3040|capacity|rate limit|too many requests|429/i.test(m)) return new AiQuotaError(m, now + 15 * 60_000);
  return null;
}

async function runModel(env: Env, model: string, item: Item, strict: boolean): Promise<unknown> {
  const messages = [
    { role: 'system', content: SYSTEM_PROMPT },
    { role: 'user', content: userPrompt(item) + (strict ? '\n\nReturn ONLY the JSON object.' : '') },
  ];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const res = (await (env.AI as any).run(model, { messages, max_tokens: 300, temperature: 0.1 })) as Record<string, unknown>;
  // Different model families return { response } or OpenAI-style { choices[0].message.content }.
  if (res && 'response' in res) return res.response;
  const choices = res?.choices as { message?: { content?: string } }[] | undefined;
  return choices?.[0]?.message?.content ?? res;
}

/** Classify one item. Retries once on invalid output; returns null if the model can't produce valid JSON. */
export async function classify(env: Env, item: Item, model = env.AI_MODEL): Promise<Classification | null> {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const out = await runModel(env, model, item, attempt > 0);
      const c = validateClassification(out);
      if (c) return c;
      log('ai.invalid', { item: item.id, attempt, sample: String(typeof out === 'string' ? out : JSON.stringify(out)).slice(0, 200) });
    } catch (err) {
      const q = quotaPause(err);
      if (q) throw q;
      logError('ai.classify', err, { item: item.id, attempt });
    }
  }
  return null;
}

/** Embeddings for several texts in ONE call (saves subrequests). */
export async function embed(env: Env, texts: string[]): Promise<number[][]> {
  if (!texts.length) return [];
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const res = (await (env.AI as any).run(env.EMBED_MODEL, { text: texts.map((t) => t.slice(0, 1000)) })) as { data: number[][] };
    return res.data;
  } catch (err) {
    throw quotaPause(err) ?? err;
  }
}

/**
 * Text used for an incident's embedding. Always title + first 200 chars of the SOURCE's
 * summary (not the AI one-liner): SIM_THRESHOLD was calibrated on exactly this recipe.
 */
export function embeddingText(title: string, rawSummary: string | null | undefined): string {
  return `${title}. ${(rawSummary ?? '').slice(0, 200)}`;
}

const EXPLAIN_PROMPT = `You are a cyber threat intelligence analyst briefing a technically literate reader.
Using ONLY the reports below, write a short explanation in plain English (max 120 words), as 3 short labelled lines:
What happened: ...
Who is affected: ...
Why it matters: ...
If a detail is not in the reports, say it is not yet known. Do not invent names, numbers or dates. No markdown, no extra lines.`;

/** "More info" button: a short grounded explanation built from the incident's reports. */
export async function explainIncident(
  env: Env,
  inc: { title: string; summary: string | null; attack_type: string | null; victim: string | null; sector: string | null; country: string | null },
  reports: { source: string; title: string; summary: string | null }[],
): Promise<string | null> {
  const context = [
    `Incident: ${inc.title}`,
    inc.summary ? `Summary: ${inc.summary}` : '',
    `Type: ${inc.attack_type ?? 'unknown'} | Victim: ${inc.victim ?? 'unknown'} | Sector: ${inc.sector ?? 'unknown'} | Country: ${inc.country ?? 'unknown'}`,
    '',
    'Reports:',
    ...reports.slice(0, 4).map((r, i) => `${i + 1}. [${r.source}] ${r.title}\n   ${(r.summary ?? '').slice(0, 500)}`),
  ]
    .filter((l) => l !== '')
    .join('\n');
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const res = (await (env.AI as any).run(env.AI_MODEL, {
      messages: [
        { role: 'system', content: EXPLAIN_PROMPT },
        { role: 'user', content: context },
      ],
      max_tokens: 260,
      temperature: 0.2,
    })) as { response?: string; choices?: { message?: { content?: string } }[] };
    const text = (res.response ?? res.choices?.[0]?.message?.content ?? '').trim();
    return text.length > 20 ? text.slice(0, 1500) : null;
  } catch (err) {
    throw quotaPause(err) ?? err;
  }
}
