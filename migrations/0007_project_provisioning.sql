-- depends: 0006_q_update_ledger

-- An idempotent provisioning request persists only digests.  Existing
-- projects predate this feature, so both columns remain nullable as a pair.
ALTER TABLE project
    ADD COLUMN provisioning_key_hash text,
    ADD COLUMN provisioning_request_hash text;

ALTER TABLE project
    ADD CONSTRAINT project_provisioning_hashes_paired
    CHECK (
        (provisioning_key_hash IS NULL AND provisioning_request_hash IS NULL)
        OR (provisioning_key_hash IS NOT NULL AND provisioning_request_hash IS NOT NULL)
    );

CREATE UNIQUE INDEX project_provisioning_key_hash_unique
    ON project (provisioning_key_hash)
    WHERE provisioning_key_hash IS NOT NULL;
