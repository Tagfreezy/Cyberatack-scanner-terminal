# CyberWatch Worker

Cloudflare Worker (TypeScript, free plan). Setup is in the [top-level README](../README.md).

## Layout

```
src/
  index.ts            HTTP routes (webhook, /admin/*) + scheduled() entry
  scheduler.ts        which sources run on which 5-minute tick; daily cleanup
  pipeline.ts         stage 1, per source: fetch → skip seen → keyword pre-filter → store 'pending'
  process.ts          stage 2: AI classify → embed → dedupe into incidents → queue alert / edit
  ai.ts               Workers AI calls, prompt, strict JSON validation + retry
  dedupe.ts           CVE / victim-name / cosine matching (pure, tested)
  scoring.ts          keyword pre-filter + fallback severity/attack-type scoring
  db.ts               D1 helpers (source state, seen-check, batched inserts, settings)
  outbox.ts           rate-limited Telegram delivery with retry/backoff
  xml.ts              tiny RSS/Atom scanner (CPU-cheap)
  http.ts             conditional GET, streamed feed reading that stops after N items
  sources/
    news.ts           Dark Reading, The Record, The Hacker News, SecurityWeek
    kev.ts            CISA KEV (streamed head only)
    ransomwarelive.ts ransomware.live RSS (default) or PRO API (with key)
  telegram/
    api.ts            Bot API client
    format.ts         HTML alert formatting (pure, tested)
    webhook.ts        update handler (owner chat only)
migrations/                schema (0001 all phases, 0002 AI/dedupe columns)
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

## Phase 2: AI + dedupe

```
fetch (stage 1) ──► items 'pending' ──► stage 2, ≤2 items per 5-min tick:
                     │                    1. classify: Llama 3.1 8B → strict JSON (validate, retry once)
 noise ──► 'filtered'│                       fails / quota out → keyword scoring (never dropped)
                                          2. embed title + source summary (qwen3-embedding, 1 call)
                                          3. match an incident from the last 72h:
                                               same CVE → same victim name → cosine ≥ 0.70
                                          4. merge (source_count+1, edit the Telegram alert)
                                             or new incident (alert if severity ≥ threshold)
```

### AI model choice (eval on 19 real items, 2026-11-03)

| Model | Correct | Invalid JSON | Avg latency |
|---|---|---|---|
| `@cf/meta/llama-3.1-8b-instruct-fp8` (chosen) | **18/19** | 0 | 5.2 s |
| `@cf/meta/llama-3.2-3b-instruct` | 14/19 | 0 | 0.6 s (rated patch notices severity 5) |
| `@cf/google/gemma-4-26b-a4b-it` | 0/19 | 19 | thinking model, uses the token budget before answering |
| `@cf/zai-org/glm-4.7-flash` | 0/19 | 19 | same |

Cost ≈ 11 neurons per item → ~1,600 of the free 10,000 neurons/day.

Embeddings: `@cf/qwen/qwen3-embedding-0.6b` (1024 dims) separated same-story pairs (≥ 0.755)
from different stories on the same topic (≤ 0.632) best of the 4 models tried; threshold 0.70.
`dedupe.check` log lines show the top scores for every item, for tuning (`npm run tail`).

### Where vectors live

D1 returns BLOBs as JS arrays (too much CPU to compare hundreds of them), so vectors go to
**Vectorize** (`cyberwatch-incidents`, free: 5M stored dims; vectors expire after 7 days ≈ 800 kept).
Vectorize applies writes with a lag (≈10 min observed), so incidents from the last 30 min also keep
their vector in D1 and are compared in-memory. Incidents without a vector (phase-1 ones, failed
upserts) are embedded by `backfillVectors` twice an hour.

### Leak-site severity

Leak posts keep the strict keyword severity (public-impact victims → 4, else 3). The AI only adds
sector + summary: in an eval on 28 posts it rated a title-insurance firm "high", and at ~65 posts/day
that would mean several false alerts daily.

### Free-plan budget per tick (50 subrequests: D1 + fetch + AI + Vectorize + Telegram)

≤2 sources × 4 · stage 2 ≈ 5 + 4 per item · backfill 4 (2×/h) · outbox 1 + 2 per message.
Measured CPU: 0–4 ms for simple requests, 5–20 ms for a feed run, 4–19 ms with 1–4 AI items.
Each AI item adds only ~2 ms; the rest is fixed per-run overhead, so AI_ITEMS_PER_RUN=2 trims the
peak a little but can't get every run under the nominal 10 ms (none were rejected so far).

### Admin

| Call | Does |
|---|---|
| `POST /admin/process` | run stage 2 now (`?backfill` also embeds old incidents) |
| `POST /admin/ai-eval` | `{model?, items?: [{title, summary, typeHint, meta}], embed?: [texts], embedModel?}` → classifications + similarity matrix |
