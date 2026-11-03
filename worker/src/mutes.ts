// Mutes. Two flavours:
//   - kind 'all'   : "/mute 2h" — quiet time. Alerts are held and land in the daily digest.
//   - kind 'group' | 'vendor' | 'victim' : the alert button "Mute <name>". Matching incidents
//     get alert_state 'muted': no instant alert, not in the digest, still counted in stats.

import { victimKey } from './dedupe';

export type MuteKind = 'all' | 'group' | 'vendor' | 'victim';

export interface Mute {
  id: number;
  kind: MuteKind;
  value: string | null; // lower-case / normalised
  until: number | null;
}

export interface MutableIncident {
  attack_type: string | null;
  group_name?: string | null;
  vendor?: string | null;
  victim?: string | null;
}

export const BUTTON_MUTE_MS = 7 * 86_400_000;

/** What the "Mute" button on an alert mutes: the ransomware group, else the vendor, else the victim. */
export function muteTarget(inc: MutableIncident): { kind: Exclude<MuteKind, 'all'>; value: string; label: string } | null {
  if (inc.group_name?.trim()) return { kind: 'group', value: inc.group_name.trim().toLowerCase(), label: inc.group_name.trim() };
  if (inc.vendor?.trim()) return { kind: 'vendor', value: inc.vendor.trim().toLowerCase(), label: inc.vendor.trim() };
  // For exploited vulns / supply chain the AI's "victim" is the affected vendor/product.
  if (inc.victim?.trim() && (inc.attack_type === 'zero-day' || inc.attack_type === 'supply-chain')) {
    return { kind: 'vendor', value: inc.victim.trim().toLowerCase(), label: inc.victim.trim() };
  }
  const key = victimKey(inc.victim);
  if (key && inc.victim) return { kind: 'victim', value: key, label: inc.victim.trim() };
  return null;
}

/** 'muted' (targeted mute), 'held' (global quiet time) or null. Expired mutes are ignored. */
export function muteStatus(inc: MutableIncident, mutes: Mute[], now = Date.now()): 'muted' | 'held' | null {
  const active = mutes.filter((m) => m.until === null || m.until > now);
  const target = muteTarget(inc);
  const vendorish = [inc.vendor, inc.attack_type === 'zero-day' || inc.attack_type === 'supply-chain' ? inc.victim : null]
    .filter((x): x is string => !!x)
    .map((x) => x.trim().toLowerCase());
  for (const m of active) {
    if (m.kind === 'group' && inc.group_name && inc.group_name.trim().toLowerCase() === m.value) return 'muted';
    if (m.kind === 'vendor' && m.value && vendorish.includes(m.value)) return 'muted';
    if (m.kind === 'victim' && target?.kind === 'victim' && target.value === m.value) return 'muted';
  }
  if (active.some((m) => m.kind === 'all')) return 'held';
  return null;
}

export async function loadMutes(db: D1Database, now = Date.now()): Promise<Mute[]> {
  const { results } = await db
    .prepare('SELECT id, kind, value, until FROM mutes WHERE until IS NULL OR until > ? ORDER BY id')
    .bind(now)
    .all<Mute>();
  return results;
}
