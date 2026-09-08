DROP INDEX IF EXISTS project_provisioning_key_hash_unique;

ALTER TABLE project
    DROP CONSTRAINT IF EXISTS project_provisioning_hashes_paired;

ALTER TABLE project
    DROP COLUMN IF EXISTS provisioning_key_hash,
    DROP COLUMN IF EXISTS provisioning_request_hash;
