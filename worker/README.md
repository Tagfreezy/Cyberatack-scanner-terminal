# CyberWatch Worker

Cloudflare Worker (TypeScript, free plan). Setup is in the [top-level README](../README.md).

## Layout

```
src/
  index.ts            HTTP routes (webhook, /admin/*) + scheduled() entry
  scheduler.ts        which sources run on which 5-minute tick; daily cleanup
  pipeline.ts         per-source: fetch → skip seen → score → store → queue alert (never throws)
  scoring.ts          keyword pre-filter + severity/attack-type scoring
  db.ts               D1 helpers (source state, seen-check, batched inserts, settings)
  outbox.ts           rate-limited Telegram delivery with retry/backoff
  xml.ts              tiny RSS/Atom scanner (CPU-cheap)
  http.ts             conditional GET (ETag / If-Modified-Since), hashing
  sources/
    news.ts           Dark Reading, The Record, The Hacker News, SecurityWeek
    kev.ts            CISA KEV (streamed head only)
    ransomwarelive.ts ransomware.live RSS (default) or PRO API (with key)
  telegram/
    api.ts            Bot API client
    format.ts         HTML alert formatting (pure, tested)
    webhook.ts        update handler (owner chat only)
migrations/0001_init.sql   schema for all phases
test/                      vitest unit tests + real feed fixtures
```

## Commands

```bash
npm test                    # unit tests (parsers, scoring, formatting, scheduler)
npm run typecheck
npm run dev                 # local worker with --test-scheduled
npm run db:migrate:local    # once, before the first `npm run dev`
npm run deploy
npm run tail                # live production logs
```

## Local testing

```bash
cp .dev.vars.example .dev.vars    # fill in values (a real bot token if you want real messages)
npm run db:migrate:local
npm run dev
```

In a second terminal:

```bash
# fire the cron exactly like Cloudflare does
curl.exe "http://localhost:8787/__scheduled?cron=*/5+*+*+*+*"
# or run specific sources now
curl.exe -X POST -H "Authorization: Bearer <API_TOKEN from .dev.vars>" "http://localhost:8787/admin/run?source=all"
curl.exe -H "Authorization: Bearer <API_TOKEN>" http://localhost:8787/admin/status
```

Inspect the local DB:
`npx wrangler d1 execute cyberwatch --local --command "SELECT severity, title FROM incidents ORDER BY id DESC LIMIT 10"`

## Sources (verified 2026-11-03)

| Source | URL | Caching | Notes |
|---|---|---|---|
| Dark Reading | `darkreading.com/rss.xml` | Last-Modified | replaced BleepingComputer, which returns 403 to Cloudflare Workers |
| The Record | `therecord.media/feed` | none | always full fetch (small feed) |
| The Hacker News | `feeds.feedburner.com/TheHackersNews` | Last-Modified only | |
| SecurityWeek | `securityweek.com/feed/` | 304 ✓ | |
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | 304 ✓ + count/dateReleased | ETag alone does **not** yield 304 there; If-Modified-Since does |
| ransomware.live | `ransomware.live/rss.xml` | — | the free **v2 API is gone** (all `/v2/*` return 404). PRO: `api-pro.ransomware.live/victims/recent`, header `X-API-KEY` |

## Severity (keyword phase)

| Kind | Severity |
|---|---|
| News with an incident signal | 2–3 by attack type, +1 critical sector, +1 large scale, capped at **4** |
| CISA KEV entry | 3, or 4 with known ransomware use |
| Leak-site claim | 3, or 4 for critical sectors (hospital, government, …) |

5 is reserved for the AI (phase 2). Alerts fire at `>= ALERT_THRESHOLD` (default 4); everything
else is kept for the daily digest (phase 3).
