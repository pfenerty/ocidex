import { createMemo, type Accessor } from "solid-js";
import { createQuery, createQueries, createMutation, useQueryClient } from "@tanstack/solid-query";
import { client, unwrap, type VulnSummary } from "~/api/client";
import { hasText } from "~/utils/format";

// ---------------------------------------------------------------------------
// Clusters and their running workloads (ADR-044, ocidex-zeta.6).
//
// A cluster is owned by a namespace, so these hooks need no visibility
// parameter: the API filters every list through visible_namespace_ids (K6).
// ---------------------------------------------------------------------------

/** useListClusters — clusters the caller can see, optionally one namespace's. */
export function useListClusters(namespaceId?: Accessor<string | undefined>) {
    // An unset filter has to send no namespace_id at all rather than an empty
    // one, which the API would read as "a namespace named ''".
    const filter = (): { namespace_id?: string } => {
        const ns = namespaceId?.();
        return hasText(ns) ? { namespace_id: ns } : {};
    };
    return createQuery(() => ({
        queryKey: ["clusters", namespaceId?.()] as const,
        queryFn: () => unwrap(client.GET("/api/v1/clusters", { params: { query: filter() } })),
        select: (resp) => ({ ...resp, data: resp.data ?? [] }),
    }));
}

/** useCluster — one cluster by id. */
export function useCluster(id: Accessor<string | undefined>) {
    return createQuery(() => ({
        queryKey: ["clusters", id()] as const,
        queryFn: () =>
            unwrap(client.GET("/api/v1/clusters/{id}", { params: { path: { id: id() ?? "" } } })),
        enabled: id() !== undefined,
    }));
}

/**
 * useClusterWorkloads — every container running in the cluster, with its match
 * state and the coverage rollup.
 *
 * Unpaginated by design: the response is one row per distinct
 * (workload, container, image), which is bounded by what the cluster actually
 * runs, and the coverage counts have to describe the same set the table shows.
 */
export function useClusterWorkloads(id: Accessor<string | undefined>) {
    return createQuery(() => ({
        queryKey: ["clusters", id(), "workloads"] as const,
        queryFn: () =>
            unwrap(
                client.GET("/api/v1/clusters/{id}/workloads", {
                    params: { path: { id: id() ?? "" } },
                }),
            ),
        enabled: id() !== undefined,
        select: (resp) => ({ ...resp, data: resp.data ?? [] }),
    }));
}

export function useCreateCluster() {
    const queryClient = useQueryClient();
    return createMutation(() => ({
        mutationFn: (body: { namespace_id: string; name: string; description?: string }) =>
            unwrap(client.POST("/api/v1/clusters", { body })),
        onSuccess: () => {
            void queryClient.invalidateQueries({ queryKey: ["clusters"] });
            void queryClient.invalidateQueries({ queryKey: ["me", "clusters"] });
        },
    }));
}

export function useUpdateCluster() {
    const queryClient = useQueryClient();
    return createMutation(() => ({
        mutationFn: ({ id, ...body }: { id: string; name: string; description?: string }) =>
            unwrap(client.PATCH("/api/v1/clusters/{id}", { params: { path: { id } }, body })),
        onSuccess: () => {
            void queryClient.invalidateQueries({ queryKey: ["clusters"] });
            void queryClient.invalidateQueries({ queryKey: ["me", "clusters"] });
        },
    }));
}

export function useDeleteCluster() {
    const queryClient = useQueryClient();
    return createMutation(() => ({
        mutationFn: (id: string) =>
            unwrap(client.DELETE("/api/v1/clusters/{id}", { params: { path: { id } } })),
        onSuccess: () => {
            void queryClient.invalidateQueries({ queryKey: ["clusters"] });
            void queryClient.invalidateQueries({ queryKey: ["me", "clusters"] });
        },
    }));
}

/** One artifact's vulnerability counts, paired back with the artifact it came from. */
export interface RunningVulnRow {
    artifactId: string;
    summary: VulnSummary | undefined;
}

export interface RunningVulnAggregate {
    isPending: boolean;
    isError: boolean;
    /** Severity totals across the distinct running artifacts, not per workload. */
    totals: VulnSummary;
    /** Per-artifact rows, in the order the artifact ids were passed. */
    rows: RunningVulnRow[];
}

const EMPTY_TOTALS: VulnSummary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
    total: 0,
};

/**
 * useRunningVulnSummaries — vulnerability counts for the images a cluster is
 * actually running.
 *
 * There is no cluster-scoped vulnerability endpoint, and adding one would
 * duplicate the digest join that /workloads already performs. So the scoping
 * happens here: the caller passes the *distinct* artifact ids of the matched
 * workloads and this fans out to the per-artifact summary each artifact page
 * already uses. De-duplication is the caller's job precisely because a single
 * artifact commonly runs as many workloads, and counting it once per workload
 * would inflate the totals into a number that means nothing.
 *
 * The query keys are identical to useArtifactVulnSummary's, so a cluster view
 * and an artifact page share one cache entry rather than double-fetching.
 */
export function useRunningVulnSummaries(
    artifactIds: Accessor<string[]>,
): Accessor<RunningVulnAggregate> {
    const results = createQueries(() => ({
        queries: artifactIds().map((id) => ({
            queryKey: ["artifact", id, "vuln-summary"] as const,
            queryFn: () =>
                unwrap(
                    client.GET("/api/v1/artifacts/{id}/vuln-summary", {
                        params: { path: { id } },
                    }),
                ),
        })),
    }));

    // Aggregated in a memo rather than through createQueries' `combine`: the
    // combined result is typed as having to extend the results array itself, so
    // a scalar rollup does not type-check there. The memo tracks the same store.
    const aggregate = createMemo(() => {
        const ids = artifactIds();
        const totals = { ...EMPTY_TOTALS };
        let isPending = false;
        let isError = false;
        const rows: RunningVulnRow[] = [];
        // Bounded by both lengths: this memo depends on the id list *and* on the
        // results store, and nothing guarantees it re-runs after the store has
        // caught up with a shortened list rather than before.
        const n = Math.min(ids.length, results.length);
        for (let i = 0; i < n; i++) {
            const r = results[i];
            if (r.isPending) isPending = true;
            if (r.isError) isError = true;
            const s = r.data?.summary;
            rows.push({ artifactId: ids[i], summary: s });
            if (s === undefined) continue;
            totals.critical += s.critical;
            totals.high += s.high;
            totals.medium += s.medium;
            totals.low += s.low;
            totals.unknown += s.unknown;
            totals.total += s.total;
        }
        return { isPending, isError, totals, rows };
    });
    return aggregate;
}
