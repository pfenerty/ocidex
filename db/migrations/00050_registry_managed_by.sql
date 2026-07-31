-- +goose Up
-- Marks a registry whose configuration is owned by an external controller — the
-- Kubernetes operator today ('kubernetes'), a Terraform provider later. Nothing
-- enforces it server-side: the owner reconciles its own spec over whatever is
-- stored, so the column exists to warn an admin that a UI edit will be reverted
-- rather than to reject the edit.
ALTER TABLE registry ADD COLUMN managed_by TEXT;
-- Identifier within the managing system: '<namespace>/<name>' for an OCIRegistry CR.
ALTER TABLE registry ADD COLUMN managed_ref TEXT;

-- +goose Down
ALTER TABLE registry DROP COLUMN managed_ref;
ALTER TABLE registry DROP COLUMN managed_by;
