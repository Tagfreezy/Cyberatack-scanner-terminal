-- Phase 2: AI classification + dedupe.
-- Items now flow: fetch → 'pending' → (AI or keyword) → 'classified' | 'rejected'.
-- Embeddings live in Vectorize (D1 returns BLOBs as JS arrays = too much CPU), so
-- incidents.embedding stays unused; `vectorized` tracks Vectorize state instead.

ALTER TABLE incidents ADD COLUMN cve TEXT;
ALTER TABLE incidents ADD COLUMN victim_key TEXT;
ALTER TABLE incidents ADD COLUMN vectorized INTEGER NOT NULL DEFAULT 0; -- 0 = no vector yet, 1 = in Vectorize, 2 = expired/deleted

CREATE INDEX idx_incidents_cve ON incidents(cve);
CREATE INDEX idx_incidents_victim_key ON incidents(victim_key);
CREATE INDEX idx_items_status ON items(status, created_at);

-- KEV incidents created in phase 1 carry the CVE id at the start of the title.
UPDATE incidents SET cve = substr(title, 1, instr(title, ':') - 1)
WHERE title LIKE 'CVE-%:%' AND cve IS NULL;
