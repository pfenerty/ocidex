-- +goose NO TRANSACTION
-- Trigram indexes for the cluster workload search (ocidex-4zfn.2), built
-- CONCURRENTLY so a populated table keeps taking inventory pushes; hence NO
-- TRANSACTION and IF [NOT] EXISTS throughout.
--
-- The search ORs ILIKE like_contains(q) over workload_name, container_name and
-- image_ref within one cluster. Measured on 145k rows (one 50k-row cluster,
-- nineteen of 5k): without these it was a parallel seq scan of the whole table,
-- 20 ms for the large cluster and 4 ms for a 5k one; with them the planner
-- BitmapOrs the three indexes, 0.2 ms and 0.1 ms.
--
-- fillfactor 70 is what makes them affordable. Every push upserts each
-- reported workload, and an unchanged workload rewrites only pod_count and
-- last_seen_at. With free space on the page that is a HOT update, which
-- touches no index; on full pages every update rewrote every index, and the
-- GIN indexes made a steady-state 5k-row push 2.2x slower (220 -> 490 ms).
-- With fillfactor 70 the same push measured ~110 ms with or without them.
-- Only new or changed workloads pay the GIN insert. The setting applies to
-- pages as they are next written; it needs no table rewrite here.

-- +goose Up
ALTER TABLE cluster_workload SET (fillfactor = 70);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cluster_workload_workload_name_trgm
    ON cluster_workload USING gin (workload_name gin_trgm_ops);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cluster_workload_container_name_trgm
    ON cluster_workload USING gin (container_name gin_trgm_ops);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cluster_workload_image_ref_trgm
    ON cluster_workload USING gin (image_ref gin_trgm_ops);

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS idx_cluster_workload_image_ref_trgm;
DROP INDEX CONCURRENTLY IF EXISTS idx_cluster_workload_container_name_trgm;
DROP INDEX CONCURRENTLY IF EXISTS idx_cluster_workload_workload_name_trgm;
ALTER TABLE cluster_workload RESET (fillfactor);
