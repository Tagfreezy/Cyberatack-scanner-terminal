// One JSON line per event: readable in `wrangler tail` and in the dashboard's Workers Logs,
// and easy to filter (e.g. `src:"securityweek" ok:false`).
export function log(event: string, data: Record<string, unknown> = {}): void {
  console.log(JSON.stringify({ event, ...data }));
}

export function logError(event: string, err: unknown, data: Record<string, unknown> = {}): void {
  const message = err instanceof Error ? err.message : String(err);
  console.error(JSON.stringify({ event, ok: false, error: message, ...data }));
}
