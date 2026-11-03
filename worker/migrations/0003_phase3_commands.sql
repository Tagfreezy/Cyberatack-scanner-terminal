-- Phase 3: commands, buttons, mutes, digests.

-- Cache for the "More info" button: the AI explanation is generated once per incident.
ALTER TABLE incidents ADD COLUMN details TEXT;

CREATE INDEX idx_mutes_until ON mutes(until);
CREATE INDEX idx_incidents_state ON incidents(alert_state, first_seen);
