# CyberWatch Terminal Dashboard

Full-screen, dark, hacker-style dashboard (Python + [Textual](https://textual.textualize.io/)) that
reads the Worker's JSON API. Works on Windows, macOS and Linux.

```
▌CYBERWATCH▐  21:47:38 Zurich │ updated 21:47:37 │ ● CISA KEV ● Dark Reading ● … │ AI on
┌ LIVE INCIDENT FEED ─────────────────────────┐┌ ATTACK MAP · 7 DAYS ──────────────┐
│ Time  Sev  Type   Incident             Cty Src││   ·····  ██▓    ·········  ▒      │
│ 21:35 MED  RANSOM Whitearmor claims …       1 ││  ███████   ·  ·············▒▒     │
│ 20:43 CRIT BREACH Binance Reveals …         3 ││     ···       ·······   ░  ·      │
│ …                                             │├ STATS ──────────┐┌ SENSORS ───────┤
│                                               ││ TODAY 89  7d 89 ││ INFOCON GREEN  │
└───────────────────────────────────────────────┘└─────────────────┘└────────────────┘
 q Quit  f Filter  o Open link  r Refresh
```

## Run it

**Windows:** double-click `run.bat`, or in Windows Terminal:

```bat
cd C:\Users\<you>\cyberwatch\terminal
run.bat
```

**macOS / Linux:**

```bash
cd cyberwatch/terminal
./run.sh
```

The first start creates a `.venv` and installs the dependencies (about a minute). It needs Python 3.11+.
Windows Terminal (or any modern terminal) gives the best colours; make the window large or full-screen.

## Configuration (`.env`)

Copy `.env.example` to `.env`:

| Variable | Meaning |
|---|---|
| `CYBERWATCH_API_URL` | your Worker URL, e.g. `https://cyberwatch.<sub>.workers.dev` |
| `CYBERWATCH_API_TOKEN` | the Worker's `API_TOKEN` secret |
| `CYBERWATCH_POLL_SECONDS` | poll interval, default 45 (15–300). New data arrives every 5 min anyway |
| `CYBERWATCH_TIMEZONE` | clock / time display, default `Europe/Zurich` |

## Keys

| Key | Action |
|---|---|
| `↑` `↓` | move in the feed |
| `Enter` | details of the selected incident (in the details view: `o` open link, `m` AI explanation, `Esc` close) |
| `f` | filter by attack type and minimum severity |
| `o` | open the selected incident's link in your browser |
| `r` | refresh now |
| `q` | quit |

## What you see

- **Live incident feed:** newest on top, coloured by severity (CRIT red, HIGH orange, MED yellow,
  LOW blue). New incidents and ones that just gained a source flash amber for 10 s. Bold = reported
  by several sources. Your selection stays on the same incident when new ones arrive.
- **Attack map:** countries with incidents in the last 7 days light up; ░▒▓█ = more incidents (log
  scale, so one busy country doesn't hide the rest). The legend lists the top countries.
- **Stats:** today and 7 days (trend vs the previous 7), 24 h activity sparkline, attack types,
  most active ransomware groups, most hit sectors.
- **Sensors:** SANS ISC data (phase 5).
- **Header:** local clock, last successful update, health dot per source (red = failing or not run
  for 3× its interval), AI status. API errors are shown here instead of crashing.

## How it stays cheap

Each poll makes 3 small requests. `/api/feed` is incremental (`?since=` cursor), and `/api/stats` reads
a snapshot the Worker precomputes on its cron, so a poll costs ~10 D1 row reads (free plan: 5M/day).

## Development

```bash
.venv/Scripts/python -m pip install -r requirements-dev.txt   # Windows (macOS/Linux: .venv/bin/python)
.venv/Scripts/python -m pytest                                 # map, model, config, full app run with a fake API
```

`cyberwatch_tui/map_data.json` is generated from [Natural Earth](https://www.naturalearthdata.com/)
110m countries (public domain) by `tools/build_map.py`: one ISO country code per map cell, so whole
countries light up. Tiny countries (Singapore, Luxembourg, …) are placed by coordinates.
