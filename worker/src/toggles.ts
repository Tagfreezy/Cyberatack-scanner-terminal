// Feature toggles, stored in D1 settings and flipped with /toggle in Telegram.
// Optional sources are OFF by default and need their secret before they can be enabled.

import type { Env } from './types';

export interface ToggleDef {
  key: string;
  label: string;
  default: boolean;
  needs?: keyof Env; // secret that must be set first
}

export const TOGGLES = {
  spikes: { key: 'toggle_spike_alerts', label: 'Port-spike alerts (SANS ISC)', default: true },
  infocon: { key: 'toggle_infocon_alerts', label: 'Infocon change alerts (SANS ISC)', default: true },
  mastodon: { key: 'toggle_mastodon', label: 'Mastodon hashtags (#ransomware #databreach #zeroday)', default: false, needs: 'MASTODON_ACCESS_TOKEN' },
  threatfox: { key: 'toggle_threatfox', label: 'abuse.ch ThreatFox malware IOCs', default: false, needs: 'THREATFOX_AUTH_KEY' },
} satisfies Record<string, ToggleDef>;

export type ToggleName = keyof typeof TOGGLES;

export async function loadToggles(env: Env): Promise<Record<ToggleName, boolean>> {
  const keys = Object.values(TOGGLES).map((t) => t.key);
  const { results } = await env.DB.prepare(`SELECT key, value FROM settings WHERE key IN (${keys.map(() => '?').join(',')})`)
    .bind(...keys)
    .all<{ key: string; value: string }>();
  const out = {} as Record<ToggleName, boolean>;
  for (const [name, def] of Object.entries(TOGGLES) as [ToggleName, ToggleDef][]) {
    const row = results.find((r) => r.key === def.key);
    const on = row ? row.value === '1' : def.default;
    // An optional source without its secret is effectively off.
    out[name] = on && (!def.needs || !!env[def.needs]);
  }
  return out;
}
