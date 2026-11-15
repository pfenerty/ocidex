-- +goose Up
-- ocidex-70eo.3: what the agent says about itself, stamped with every accepted
-- snapshot. Nullable throughout: an agent that predates the field sends none of
-- it, and a cluster that has never reported has nothing to say.
ALTER TABLE cluster
    ADD COLUMN agent_version                 TEXT,
    ADD COLUMN agent_kubernetes_version      TEXT,
    ADD COLUMN agent_node_count              INTEGER,
    ADD COLUMN agent_namespaces              TEXT[],
    ADD COLUMN agent_report_interval_seconds INTEGER,
    ADD COLUMN agent_pod_name                TEXT,
    ADD COLUMN agent_pod_namespace           TEXT;

COMMENT ON COLUMN cluster.agent_version IS
    'Version the agent reported with its last accepted snapshot; NULL for an agent that predates self-reporting.';
COMMENT ON COLUMN cluster.agent_kubernetes_version IS
    'Kubernetes server gitVersion the agent read from the discovery API.';
COMMENT ON COLUMN cluster.agent_node_count IS
    'Distinct nodes running the reported pods. Derived from the pods, not a node list: the agent has no RBAC on nodes.';
COMMENT ON COLUMN cluster.agent_namespaces IS
    'The agent''s namespace allowlist. Empty array means every namespace; NULL means not reported.';
COMMENT ON COLUMN cluster.agent_report_interval_seconds IS
    'Seconds between snapshots. 0 for a one-shot (--once) agent.';

-- +goose Down
ALTER TABLE cluster
    DROP COLUMN agent_version,
    DROP COLUMN agent_kubernetes_version,
    DROP COLUMN agent_node_count,
    DROP COLUMN agent_namespaces,
    DROP COLUMN agent_report_interval_seconds,
    DROP COLUMN agent_pod_name,
    DROP COLUMN agent_pod_namespace;
