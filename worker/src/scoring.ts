import type { AttackType, Item, Score } from './types';

// Keyword scoring. In phase 1 it is the classifier; from phase 2 on it acts as the
// pre-filter (keeps noise away from Workers AI) and as the fallback when AI is down.
// Keyword scores are capped at 4: severity 5 is reserved for the AI's judgement.

interface Signal {
  re: RegExp;
  type: AttackType;
  weight: number;
}

const SIGNALS: Signal[] = [
  { re: /\bransomware\b|\bextortion gang\b|\bleak site\b/i, type: 'ransomware', weight: 2 },
  { re: /\bwiper\b/i, type: 'wiper', weight: 2 },
  // Exploitation happening now, not "could be exploited" (lookbehind skips hypotheticals).
  { re: /\bzero[- ]day\b|\b0-day\b|actively exploited|(?<!(could|can|may|might) be )\bexploited\b|under active exploitation|\b(hackers|attackers|threat actors|cybercriminals|apts?)\s+(exploit|abuse)|\bongoing (\w+ ){0,2}attacks\b/i, type: 'zero-day', weight: 2 },
  { re: /supply[- ]chain (attack|compromise)|malicious (npm|pypi|packages?|extensions?)|backdoored|trojani[sz]ed|(update|package|repository|channel|build)( \w+)? (hijacked|compromised)/i, type: 'supply-chain', weight: 2 },
  { re: /\bddos\b|denial[- ]of[- ]service/i, type: 'ddos', weight: 2 },
  { re: /data breach|\bbreach(ed|es)?\b|\bhack(ed)?\b|\bhack of\b|data (leak|theft)|\bleaked\b|stolen data|data stolen|unauthori[sz]ed access|\bcompromised\b|\bintrusion\b|\bexposed\b.*\b(records|data)\b/i, type: 'breach', weight: 2 },
  { re: /cyber[- ]?attack/i, type: 'other', weight: 2 },
  // Two weak signals together (an actor + an impact) are enough; one alone is not.
  { re: /\bhackers?\b|\battackers?\b|\bthreat actors?\b|\bcybercriminals?\b|\bgang\b/i, type: 'other', weight: 1 },
  { re: /\bheist\b|\btheft\b|\bsteal(s|ing)?\b|\bstole\b|\bdisrupt(ed|ion|s)?\b|\boutage\b|\boffline\b|\bextort|\bbackdoors?\b|\bhijack(ed|s)?\b/i, type: 'other', weight: 1 },
];

/** Never incident reports, whatever keywords they contain ("X raises $50M to fight ransomware"). */
const HARD_NOISE =
  /\bwebinar\b|\bpodcast\b|\bdeals?\b|\bsponsored\b|\braises \$|\bfunding\b|\bacquires?\b|\bacquisition\b|\bpartnership\b|\bappoints?\b|\bhires\b|\bconference\b|\baward|\brecap\b|\broundup\b|week in review|\bm&a\b/i;

/** Usually not incidents, but a strong incident signal in the title wins. */
const SOFT_NOISE =
  /\bhow to\b|\btutorial\b|\btips\b|\bguide\b|\bchecklist\b|\breview\b|\bbest\b|\bnewsletter\b|\binterview\b|\bexplained\b|\blaunch(es|ed)?\b|\bunveils?\b|\bpredicts?\b|\bsurvey\b/i;

const CRITICAL_SECTOR =
  /\bhospitals?\b|\bhealth ?care\b|\bmedical\b|\bgovernment\b|\bministry\b|\bfederal\b|\bmilitary\b|\bdefen[cs]e\b|\bairports?\b|\bairlines?\b|\benergy\b|\bpower grid\b|\butility\b|\bwater\b|\bpipeline\b|\bnuclear\b|\bbanks?\b|\btelecoms?\b|\belection\b|\bcritical infrastructure\b/i;

const LEAK_CRITICAL =
  /\bhospitals?\b|\bhealth ?(system|care network)\b|\bmedical cent(er|re)\b|\bgovernment (administration|agency|department)\b|\b(local|state|federal|national) government\b|\bministry\b|\bmunicipality\b|\bcity of\b|\b(county|city) (government|council|sheriff|commission)\b|\bcounty of\b|\bschool district\b|\bpolice\b|\bairport\b|\butility company\b|\bpower (company|utility)\b/i;

const LARGE_SCALE =
  /\b\d+(\.\d+)?\s*(million|billion|m)\b|\b\d{3},\d{3}\b|\bmillions\b|\bnationwide\b|\bworldwide\b|\bglobal(ly)?\b|\bmass(ive)?\b|\bwidespread\b|\bthousands of\b/i;

export const BASE_SEVERITY: Record<AttackType, number> = {
  ransomware: 3,
  'zero-day': 3,
  'supply-chain': 3,
  wiper: 3,
  breach: 2,
  ddos: 2,
  other: 2,
};

export function isHardNoise(item: Item): boolean {
  if (item.meta.author && /sponsored/i.test(item.meta.author)) return true;
  return HARD_NOISE.test(item.title);
}

export function scoreItem(item: Item): Score {
  if (item.typeHint === 'kev') {
    const known = item.meta.knownRansomware === true;
    return {
      isIncident: true,
      attackType: known ? 'ransomware' : 'zero-day',
      severity: known ? 4 : 3,
      reasons: ['cisa-kev', ...(known ? ['known-ransomware-use'] : [])],
    };
  }

  if (item.typeHint === 'leak') {
    // Leak-site blurbs are long company descriptions, so the broad sector list would fire on
    // ~10% of posts ("water treatment", "defense attorneys"). Only public-impact victims bump.
    const head = `${item.meta.victim ?? ''} ${item.meta.sector ?? ''} ${item.summary.slice(0, 160)}`;
    const critical = LEAK_CRITICAL.test(head);
    return {
      isIncident: true,
      attackType: 'ransomware',
      severity: critical ? 4 : 3,
      reasons: ['leak-site', ...(critical ? ['critical-sector'] : [])],
    };
  }

  // News: title counts fully, summary only confirms (summaries mention lots of things).
  const reasons: string[] = [];
  let points = 0;
  // Attack type: strongest headline signal (SIGNALS order breaks ties); summary only as fallback.
  let bestTitle: Signal | null = null;
  let bestSummary: Signal | null = null;
  for (const s of SIGNALS) {
    if (s.re.test(item.title)) {
      points += s.weight;
      reasons.push(`title:${s.type}`);
      if (!bestTitle || s.weight > bestTitle.weight) bestTitle = s;
    } else if (s.re.test(item.summary)) {
      points += 1;
      reasons.push(`summary:${s.type}`);
      if (!bestSummary || s.weight > bestSummary.weight) bestSummary = s;
    }
  }
  const best = bestTitle && bestTitle.weight >= (bestSummary?.weight ?? 0) ? bestTitle : (bestSummary ?? bestTitle);

  const strong = bestTitle !== null && bestTitle.weight >= 2;
  if (isHardNoise(item) || (SOFT_NOISE.test(item.title) && !strong)) {
    return { isIncident: false, attackType: 'other', severity: 1, reasons: ['noise', ...reasons] };
  }
  // The headline must carry at least one signal; summaries alone mention too much.
  if (points < 2 || !best || !bestTitle) {
    return { isIncident: false, attackType: best?.type ?? 'other', severity: 1, reasons };
  }

  const text = `${item.title} ${item.summary}`;
  let severity = BASE_SEVERITY[best.type];
  if (CRITICAL_SECTOR.test(text)) {
    severity++;
    reasons.push('critical-sector');
  }
  if (LARGE_SCALE.test(text)) {
    severity++;
    reasons.push('large-scale');
  }
  return { isIncident: true, attackType: best.type, severity: Math.min(4, severity), reasons };
}
