# CyberWatch

Live monitor for major cyberattacks. It collects reports from free public sources, scores
and (from phase 2) AI-classifies them, sends alerts to your Telegram bot, and
(from phase 4) shows everything in a full-screen terminal dashboard.

```
            ┌───────────────── Cloudflare Worker (free plan) ─────────────────┐
 RSS feeds ─┤  cron every 5 min → one slice of sources per tick                │
 CISA KEV  ─┤  fetch → normalize → skip seen (D1) → score → incidents (D1)     ├─► Telegram (alerts, /commands)
 ransomware.┤  outbox → Telegram, ~1 msg/s                                     ├─► /api/* → terminal dashboard (phase 4)
 live      ─┤  /telegram/webhook   /admin/*   /api/*                           │
            └──────────────────────────────────────────────────────────────────┘
```

| Folder | What |
|---|---|
| [`worker/`](worker/README.md) | Cloudflare Worker (TypeScript): sources, scoring, D1, Telegram |
| [`terminal/`](terminal/README.md) | Python + Textual dashboard (phase 4) |

## Status

| Phase | Content | State |
|---|---|---|
| 1 | Worker skeleton, D1 schema, RSS + CISA KEV + ransomware.live, keyword scoring, basic alerts | ✅ built + tested locally |
| 2 | Workers AI classification, dedupe into incidents, message editing, fallback | ⏳ |
| 3 | Telegram commands, buttons, mutes, daily digest, weekly report | ⏳ |
| 4 | JSON API + Textual terminal dashboard | ⏳ |
| 5 | SANS ISC sensor data, spike alerts, optional sources | ⏳ |

---

## Setup, step by step (Windows / macOS / Linux)

You need **Node.js 20+** (`node --version`). Python 3.11+ is only needed from phase 4.

> **Windows/PowerShell:** use `curl.exe`, not `curl` (in Windows PowerShell `curl` is an
> alias for `Invoke-WebRequest` and the flags below won't work).

### 1. Install the worker's dependencies

```bash
cd cyberwatch/worker
npm install
```

### 2. Cloudflare account + login

1. Create a free account at <https://dash.cloudflare.com/sign-up> and verify your email.
2. Log wrangler in (opens your browser):
   ```bash
   npx wrangler login
   ```
3. Check: `npx wrangler whoami` shows your account.

### 3. Create the D1 database

```bash
npx wrangler d1 create cyberwatch
```

Copy the printed `database_id` into `worker/wrangler.jsonc`, replacing
`REPLACE_WITH_D1_DATABASE_ID`. Then create the tables:

```bash
npm run db:migrate:remote
```

### 4. Telegram bot + your chat ID

1. In Telegram, talk to **@BotFather** → `/newbot` → pick a name → you get a **bot token**
   like `123456789:AA...`. Keep it secret.
2. Open your new bot and send it any message (e.g. `hi`).
3. In a browser open `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates`
   and find `"chat":{"id":123456789,...}`. That number is your **chat ID**.
   (Do this *before* step 7. Once a webhook is set, `getUpdates` stops working.)

### 5. Deploy

```bash
npm run deploy
```

Note the URL it prints, e.g. `https://cyberwatch.<your-subdomain>.workers.dev`.
(The first time, wrangler may ask you to pick a `workers.dev` subdomain.)

### 6. Set the secrets

Generate two random strings, one for the API token and one for the webhook secret:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Then set each secret (wrangler prompts for the value, so nothing lands in your shell history):

```bash
npx wrangler secret put TELEGRAM_BOT_TOKEN       # from BotFather
npx wrangler secret put TELEGRAM_CHAT_ID         # from step 4
npx wrangler secret put TELEGRAM_WEBHOOK_SECRET  # random string #1
npx wrangler secret put API_TOKEN                # random string #2 (keep it, the dashboard needs it)
```

Optional: `RANSOMWARE_LIVE_API_KEY` (free PRO key from <https://my.ransomware.live>).

### 7. Connect Telegram to the worker

```bash
curl.exe -X POST -H "Authorization: Bearer <API_TOKEN>" https://cyberwatch.<sub>.workers.dev/admin/setup-webhook
```

This calls `setWebhook` (with the secret token) and `setMyCommands` for you.

### 8. Test alert

```bash
curl.exe -X POST -H "Authorization: Bearer <API_TOKEN>" https://cyberwatch.<sub>.workers.dev/admin/test-alert
```

Your phone should buzz with a 🟠 HIGH test alert. Then send `/status` to the bot.

### 9. Watch it run

```bash
npm run tail          # live logs: one JSON line per source run, with ok/error
```

The cron runs every 5 minutes. **The first run of each source is a silent baseline**:
it stores what's already in the feeds without alerting, so a fresh deploy doesn't flood
your phone. Alerts start with the first *new* article after that.

Useful admin calls (all need the bearer token):

| Call | Does |
|---|---|
| `GET /admin/status` | source health, counters |
| `POST /admin/run?source=ransomware.live` | run one source now (`bleepingcomputer`, `therecord`, `thehackernews`, `securityweek`, `cisa-kev`, `ransomware.live`). Prefer one at a time: `?source=all` also works but puts every source into one invocation, close to the free plan's 50-D1-queries limit |
| `POST /admin/test-alert` | send a sample alert |
| `POST /admin/setup-webhook` | (re)register webhook + commands |

---

## Free-plan design notes

- **One cron trigger** (`*/5`). The free plan allows 5 per *account*, so the worker decides
  internally what each tick runs: one news feed per tick (each feed every 20 min),
  ransomware.live every 15 min, CISA KEV hourly.
- **10 ms CPU**: RSS is scanned with `indexOf`, not a DOM parser, and only the newest 20 items.
  The 1.8 MB KEV file is *streamed*: only the first 96 KB is read (it's newest-first), the rest
  is cancelled. Waiting on the network doesn't count toward CPU.
- **Conditional requests**: `If-None-Match` / `If-Modified-Since` everywhere. BleepingComputer,
  SecurityWeek and CISA answer `304 Not Modified`, so most runs parse nothing. KEV additionally
  compares `count` + `dateReleased`.
- **Telegram limits**: alerts go through a D1 outbox, at most 5 per run, 1.1 s apart; the rest
  go out on the next tick. On HTTP 429 the worker honours `retry_after`.
- **Isolation**: every source runs inside its own try/catch and records success or failure in
  `source_state`, so one broken feed never stops the others.
