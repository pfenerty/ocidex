-- Kubernetes deployment inventory (ADR-044, ocidex-zeta.2).
--
-- Two tables. `cluster` is a registered reporting cluster; `cluster_workload`
-- is the current state of what that cluster says is running.
--
-- A cluster is owned by a namespace and carries no visibility column of its
-- own, exactly like `source` (ADR-039, ADR-044 K6). Every read path filters
-- with `namespace_id IN (SELECT visible_namespace_ids(...))` — the set-returning
-- form, for the reason 00052 and 00053 both record: a per-row EXISTS costs one
-- lookup per workload row.
--
-- `cluster_workload` is a CURRENT-STATE table, not a history. Snapshots are
-- full replacements: the ingest path upserts everything reported and deletes
-- the rows for that cluster the snapshot did not mention, in one transaction
-- (K7). A workload that stops running is deleted rather than tombstoned —
-- "what used to run here" is a retention question this migration deliberately
-- does not answer.
--
-- The join to catalogued data is by digest and lives entirely in the query
-- layer; there is no artifact_id or sbom_id column here. Storing a resolved id
-- would freeze the match at snapshot time, so a workload would stay "unknown"
-- forever after its SBOM was finally ingested. Deriving it per read means
-- coverage improves retroactively, which is the whole point of K4.

-- +goose Up

-- +goose StatementBegin
CREATE TABLE cluster (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace_id UUID        NOT NULL REFERENCES namespace (id) ON DELETE CASCADE,
    name         TEXT        NOT NULL,
    description  TEXT        NOT NULL DEFAULT '',
    last_seen_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (namespace_id, name)
);
-- +goose StatementEnd

COMMENT ON TABLE cluster IS
    'A registered Kubernetes cluster reporting its running workloads (ADR-044). Owned by a namespace; visibility is inherited from it, never stored here.';
COMMENT ON COLUMN cluster.last_seen_at IS
    'Stamped on every accepted inventory snapshot. NULL means no agent has ever reported. Staleness is how a dead agent is distinguished from an empty cluster (ADR-044 K2) — a cluster showing zero workloads because nothing reported must never read as a cluster running nothing.';

CREATE INDEX idx_cluster_namespace_id ON cluster (namespace_id);

-- +goose StatementBegin
CREATE TABLE cluster_workload (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id     UUID        NOT NULL REFERENCES cluster (id) ON DELETE CASCADE,
    k8s_namespace  TEXT        NOT NULL,
    workload_kind  TEXT        NOT NULL,
    workload_name  TEXT        NOT NULL,
    container_name TEXT        NOT NULL,
    image_ref      TEXT        NOT NULL,
    image_digest   TEXT,
    pod_count      INTEGER     NOT NULL DEFAULT 1 CHECK (pod_count >= 0),
    first_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT cluster_workload_digest_form
        CHECK (image_digest IS NULL OR image_digest ~ '^sha256:[0-9a-f]{64}$')
);
-- +goose StatementEnd

COMMENT ON TABLE cluster_workload IS
    'Current running-image inventory reported by a cluster agent. Full-snapshot semantics: rows absent from a snapshot are deleted (ADR-044 K7). Not a history table.';
COMMENT ON COLUMN cluster_workload.image_digest IS
    'Normalized sha256 digest read from status.containerStatuses[].imageID. NULL means the agent could not extract a digest at all (ADR-044 K5 "unresolvable") — distinct from a digest that matches no ingested SBOM ("unknown"), because the remedy differs: investigate the node runtime versus ingest an SBOM.';
COMMENT ON COLUMN cluster_workload.image_ref IS
    'The image reference for display only. Never a join key: a tag is mutable and is not an identity (ADR-044 K3).';
COMMENT ON COLUMN cluster_workload.pod_count IS
    'How many running pods of this workload carry this container at this digest. Greater than one is normal; two rows for one container differing only by digest is a rollout in progress.';

-- The natural key is (workload, container, digest) rather than (workload,
-- container): during a rolling update two pods of one Deployment legitimately
-- run different digests, and collapsing them would hide exactly the half of a
-- rollout that still carries the vulnerability.
--
-- NULLS NOT DISTINCT (PG 15+) is required, not incidental: without it every
-- unresolvable row (image_digest IS NULL) is unique to itself, so the ingest
-- upsert would never match one and would accumulate a duplicate per snapshot.
CREATE UNIQUE INDEX idx_cluster_workload_identity
    ON cluster_workload (cluster_id, k8s_namespace, workload_kind, workload_name, container_name, image_digest)
    NULLS NOT DISTINCT;

-- The digest join runs in the other direction — given the visible workloads,
-- find their SBOMs — so this index serves the prune/scan side and grouping by
-- digest across a cluster.
CREATE INDEX idx_cluster_workload_digest
    ON cluster_workload (image_digest)
    WHERE image_digest IS NOT NULL;

-- sbom.digest already has a unique index (00006). sbom.index_digest does not,
-- and tier 2 of the join (ADR-044 K4) probes it for every unmatched workload.
CREATE INDEX idx_sbom_index_digest
    ON sbom (index_digest)
    WHERE index_digest IS NOT NULL;

-- +goose Down

DROP INDEX IF EXISTS idx_sbom_index_digest;
DROP TABLE IF EXISTS cluster_workload;
DROP TABLE IF EXISTS cluster;
