-- CyberWatch schema. Designed for all phases up front so later phases only add data,
-- not breaking changes. Timestamps are unix epoch milliseconds (INTEGER).

-- Every raw item seen from any source (news article, KEV entry, leak-site post, ...).
CREATE TABLE items (
  id            TEXT PRIMARY KEY,          -- "<source>:<stable id>"
  source        TEXT NOT NULL,
  title         TEXT NOT NULL,
  url           TEXT,
  published_at  INTEGER,
  summary       TEXT,
  type_hint     TEXT,                      -- news | kev | leak | sensor | social
  status        TEXT NOT NULL,             -- baseline | filtered | scored | classified
  is_incident   INTEGER NOT NULL DEFAULT 0,
  severity      INTEGER NOT NULL DEFAULT 0,
  attack_type   TEXT,
  incident_id   INTEGER,
  meta          TEXT,                      -- source-specific JSON (group, country, cve, ...)
  created_at    INTEGER NOT NULL
);
CREATE INDEX idx_items_created ON items(created_at);
CREATE INDEX idx_items_incident ON items(incident_id);

-- One real-world attack, possibly reported by several sources (dedupe in phase 2).
CREATE TABLE incidents (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  title               TEXT NOT NULL,
  summary             TEXT,
  url                 TEXT,
  attack_type         TEXT,                -- ransomware | breach | ddos | zero-day | supply-chain | wiper | other
  victim              TEXT,
  group_name          TEXT,                -- ransomware group / threat actor
  vendor              TEXT,                -- for KEV / zero-days
  sector              TEXT,
  country             TEXT,                -- ISO-3166 alpha-2
  severity            INTEGER NOT NULL,
  source_count        INTEGER NOT NULL DEFAULT 1,
  sources             TEXT,                -- JSON array of source names
  classified_by       TEXT,                -- keywords | ai
  embedding           BLOB,                -- Float32 vector (phase 2)
  first_seen          INTEGER NOT NULL,
  last_seen           INTEGER NOT NULL,
  alert_state         TEXT NOT NULL DEFAULT 'none', -- none | queued | sent | digest | muted | baseline
  telegram_message_id INTEGER,
  digested_at         INTEGER
);
CREATE INDEX idx_incidents_first_seen ON incidents(first_seen);
CREATE INDEX idx_incidents_last_seen ON incidents(last_seen);
CREATE INDEX idx_incidents_victim ON incidents(victim);

-- Telegram messages waiting to be sent/edited. Drained a few per cron run to respect
-- Telegram's ~1 msg/s/chat limit and the Workers 50-subrequest limit.
CREATE TABLE outbox (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  kind            TEXT NOT NULL,           -- alert | edit | text
  incident_id     INTEGER,
  payload         TEXT NOT NULL,           -- JSON (text, reply_markup, ...)
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL,
  last_error      TEXT,
  created_at      INTEGER NOT NULL,
  sent_at         INTEGER
);
CREATE INDEX idx_outbox_pending ON outbox(sent_at, next_attempt_at);

-- Mutes: kind = all | group | vendor | type. value is lower-case.
CREATE TABLE mutes (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  kind       TEXT NOT NULL,
  value      TEXT,
  until      INTEGER,                      -- NULL = forever
  created_at INTEGER NOT NULL
);

CREATE TABLE settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Per-source health + HTTP cache validators.
CREATE TABLE source_state (
  source         TEXT PRIMARY KEY,
  etag           TEXT,
  last_modified  TEXT,
  initialized    INTEGER NOT NULL DEFAULT 0, -- 0 = next run is a silent baseline
  last_run       INTEGER,
  last_ok        INTEGER,
  last_error     TEXT,
  last_error_at  INTEGER,
  last_fetched   INTEGER NOT NULL DEFAULT 0,
  last_new       INTEGER NOT NULL DEFAULT 0,
  extra          TEXT                        -- JSON, source-specific (e.g. KEV count/dateReleased)
);

-- SANS ISC snapshots (phase 5).
CREATE TABLE sensor_snapshots (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  kind       TEXT NOT NULL,                -- infocon | topports | topsources | spikes
  data       TEXT NOT NULL,                -- JSON
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_sensor_kind ON sensor_snapshots(kind, created_at);
