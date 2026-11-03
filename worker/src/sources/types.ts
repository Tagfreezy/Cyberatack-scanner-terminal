import type { Env, Item, SourceState } from '../types';

export interface SourceResult {
  /** null = upstream said "not modified" (304) or content unchanged → nothing to do. */
  items: Item[] | null;
  etag?: string | null;
  lastModified?: string | null;
  /** Source-specific state saved to source_state.extra after a successful run. */
  extra?: unknown;
}

export interface Source {
  name: string;
  label: string;
  run(env: Env, state: SourceState | null): Promise<SourceResult>;
}
