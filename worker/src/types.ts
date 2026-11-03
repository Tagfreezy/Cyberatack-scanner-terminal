export interface Env {
  DB: D1Database;
  AI: Ai;
  VECTORS: VectorizeIndex;

  AI_MODEL: string;
  EMBED_MODEL: string;
  SIM_THRESHOLD: string;
  AI_ITEMS_PER_RUN: string;

  // vars (wrangler.jsonc)
  ALERT_THRESHOLD: string;
  TIMEZONE: string;
  USER_AGENT: string;
  MAX_TELEGRAM_SENDS_PER_RUN: string;
  RSS_MAX_ITEMS: string;

  // secrets
  TELEGRAM_BOT_TOKEN: string;
  TELEGRAM_CHAT_ID: string;
  TELEGRAM_WEBHOOK_SECRET: string;
  API_TOKEN: string;
  RANSOMWARE_LIVE_API_KEY?: string;
  // optional sources (phase 5)
  MASTODON_INSTANCE: string;
  MASTODON_ACCESS_TOKEN?: string;
  THREATFOX_AUTH_KEY?: string;
}

export type TypeHint = 'news' | 'kev' | 'leak' | 'sensor' | 'social';

export type AttackType =
  | 'ransomware'
  | 'breach'
  | 'ddos'
  | 'zero-day'
  | 'supply-chain'
  | 'wiper'
  | 'other';

/** The one normalized shape every source produces. */
export interface Item {
  id: string; // "<source>:<stable id>"
  source: string;
  title: string;
  url: string | null;
  publishedAt: number | null; // epoch ms
  summary: string;
  typeHint: TypeHint;
  meta: ItemMeta;
}

export interface ItemMeta {
  group?: string; // ransomware group
  victim?: string;
  country?: string; // ISO-2
  sector?: string;
  vendor?: string;
  product?: string;
  cve?: string;
  knownRansomware?: boolean;
  categories?: string[];
  author?: string;
}

export interface Score {
  isIncident: boolean;
  severity: number; // 1-5
  attackType: AttackType;
  reasons: string[];
}

/** Response of one HTTP fetch, with cache-validator handling. */
export interface FetchOutcome {
  notModified: boolean;
  etag: string | null;
  lastModified: string | null;
}

export interface SourceState {
  source: string;
  etag: string | null;
  last_modified: string | null;
  initialized: number;
  extra: string | null;
}
