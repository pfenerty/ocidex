import type { Accessor } from "solid-js";
import { createQuery, createMutation, useQueryClient } from "@tanstack/solid-query";
import { client, unwrap, type WorkloadMatchState } from "~/api/client";
import type { paths } from "~/types/openapi";
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

/** Filters and paging for the workload table. */
export interface WorkloadQueryParams {
    k8s_namespace?: string;
    match_state?: WorkloadMatchState;
    q?: string;
    sort?: WorkloadSortKey;
    dir?: SortDir;
    limit?: number;
    offset?: number;
}

/** The columns the API will order the workload list by. */
export type WorkloadSortKey =
    NonNullable<paths["/api/v1/clusters/{id}/workloads"]["get"]["parameters"]["query"]>["sort"];

export type SortDir = "asc" | "desc";

/**
 * useClusterWorkloads — the containers running in the cluster, with each row's
 * match state, the coverage rollup, and pagination.
 *
 * The coverage counts describe the whole cluster whatever the filters say. That
 * is the point of them: a filtered table showing three clean rows must not read
 * as a clean cluster (ADR-044 K5).
 */
export function useClusterWorkloads(
    id: Accessor<string | undefined>,
    params?: Accessor<WorkloadQueryParams>,
) {
    // Empty strings are dropped rather than sent: the API would read
    // `match_state=` as a filter for a state named "".
    const query = (): WorkloadQueryParams => {
        const p = params?.() ?? {};
        const state = p.match_state;
        return {
            ...(hasText(p.k8s_namespace) ? { k8s_namespace: p.k8s_namespace } : {}),
            ...(state !== undefined ? { match_state: state } : {}),
            ...(hasText(p.q) ? { q: p.q } : {}),
            ...(p.sort !== undefined ? { sort: p.sort } : {}),
            ...(p.dir !== undefined ? { dir: p.dir } : {}),
            ...(p.limit !== undefined ? { limit: p.limit } : {}),
            ...(p.offset !== undefined ? { offset: p.offset } : {}),
        };
    };
    return createQuery(() => ({
        queryKey: ["clusters", id(), "workloads", query()] as const,
        queryFn: () =>
            unwrap(
                client.GET("/api/v1/clusters/{id}/workloads", {
                    params: { path: { id: id() ?? "" }, query: query() },
                }),
            ),
        enabled: id() !== undefined,
        select: (resp) => ({ ...resp, data: resp.data ?? [] }),
    }));
}

/**
 * useClusterNamespaces — the namespace facet for the workload filter.
 *
 * Separate from the workload page because it describes the whole cluster: built
 * from a page of rows the filter would only ever offer the namespaces that page
 * happened to contain.
 */
export function useClusterNamespaces(id: Accessor<string | undefined>) {
    return createQuery(() => ({
        queryKey: ["clusters", id(), "k8s-namespaces"] as const,
        queryFn: () =>
            unwrap(
                client.GET("/api/v1/clusters/{id}/k8s-namespaces", {
                    params: { path: { id: id() ?? "" } },
                }),
            ),
        enabled: id() !== undefined,
        select: (resp) => ({ ...resp, data: resp.data ?? [] }),
    }));
}

/** Filters and paging for the running-vulnerability list. */
export type VulnSeverityFilter = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface ClusterVulnQueryParams {
    severity?: VulnSeverityFilter;
    sort?: ClusterVulnSortKey;
    dir?: SortDir;
    limit?: number;
    offset?: number;
}

/** The columns the API will order the running-vulnerability list by. */
export type ClusterVulnSortKey =
    NonNullable<paths["/api/v1/clusters/{id}/vulns"]["get"]["parameters"]["query"]>["sort"];

/**
 * useClusterVulns — vulnerabilities carried by the images the cluster is
 * actually running, counted once per advisory rather than once per workload.
 *
 * This replaces a per-artifact fan-out the browser used to do. The server keys
 * the rollup by canonical id, so aliased advisories (GO-…, GHSA-…, CVE-…)
 * collapse into one row instead of appearing three times with a third of the
 * workload count each.
 */
export function useClusterVulns(
    id: Accessor<string | undefined>,
    params?: Accessor<ClusterVulnQueryParams>,
) {
    const query = (): ClusterVulnQueryParams => {
        const p = params?.() ?? {};
        const severity = p.severity;
        return {
            ...(severity !== undefined ? { severity } : {}),
            ...(p.sort !== undefined ? { sort: p.sort } : {}),
            ...(p.dir !== undefined ? { dir: p.dir } : {}),
            ...(p.limit !== undefined ? { limit: p.limit } : {}),
            ...(p.offset !== undefined ? { offset: p.offset } : {}),
        };
    };
    return createQuery(() => ({
        queryKey: ["clusters", id(), "vulns", query()] as const,
        queryFn: () =>
            unwrap(
                client.GET("/api/v1/clusters/{id}/vulns", {
                    params: { path: { id: id() ?? "" }, query: query() },
                }),
            ),
        enabled: id() !== undefined,
        select: (resp) => ({ ...resp, data: resp.data ?? [] }),
    }));
}

/**
 * useVulnWorkloads — which running workloads carry one advisory.
 *
 * The reverse of useClusterVulns. Omit clusterId to ask across every cluster
 * the caller can see, which is the question the catalog page could not answer
 * before: "am I actually running this?"
 *
 * The id is a canonical id, so an advisory published under several native ids
 * answers the same for all of them.
 */
export function useVulnWorkloads(
    canonicalId: Accessor<string | undefined>,
    clusterId?: Accessor<string | undefined>,
    options?: Accessor<{ enabled?: boolean; limit?: number }>,
) {
    const query = (): { cluster_id?: string; limit?: number } => {
        const cid = clusterId?.();
        const limit = options?.().limit;
        return {
            ...(hasText(cid) ? { cluster_id: cid } : {}),
            ...(limit !== undefined ? { limit } : {}),
        };
    };
    return createQuery(() => ({
        queryKey: ["vulns", canonicalId(), "workloads", query()] as const,
        queryFn: () =>
            unwrap(
                client.GET("/api/v1/vulns/{id}/workloads", {
                    params: { path: { id: canonicalId() ?? "" }, query: query() },
                }),
            ),
        // Row expansion mounts this hook before the row is opened, so the
        // caller gates it rather than fetching every advisory's workloads up
        // front.
        enabled: canonicalId() !== undefined && (options?.().enabled ?? true),
        select: (resp) => ({ ...resp, data: resp.data ?? [] }),
    }));
}

/**
 * useClusterUnknownImages — the No-SBOM gap grouped by image, each row carrying
 * the registry that would serve it or the reason none would.
 *
 * Grouped server-side: twelve replicas of one unscanned image are one thing to
 * ingest, and the count has to describe the cluster rather than a page of it.
 */
export function useClusterUnknownImages(
    id: Accessor<string | undefined>,
    options?: Accessor<{ enabled?: boolean; limit?: number }>,
) {
    const query = (): { limit?: number } => {
        const limit = options?.().limit;
        return limit === undefined ? {} : { limit };
    };
    return createQuery(() => ({
        queryKey: ["clusters", id(), "unknown-images", query()] as const,
        queryFn: () =>
            unwrap(
                client.GET("/api/v1/clusters/{id}/unknown-images", {
                    params: { path: { id: id() ?? "" }, query: query() },
                }),
            ),
        enabled: id() !== undefined && (options?.().enabled ?? true),
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
        mutationFn: ({
            id,
            ...body
        }: {
            id: string;
            name: string;
            description?: string;
            // Omitted rather than sent as false when the caller isn't editing
            // it: the API reads an absent auto_ingest as "leave it alone", so a
            // rename cannot switch ingest off as a side effect.
            auto_ingest?: boolean;
        }) => unwrap(client.PATCH("/api/v1/clusters/{id}", { params: { path: { id } }, body })),
        onSuccess: () => {
            void queryClient.invalidateQueries({ queryKey: ["clusters"] });
            void queryClient.invalidateQueries({ queryKey: ["me", "clusters"] });
        },
    }));
}

/**
 * useIngestUnknown — queue scans for the cluster's unscanned running images.
 *
 * Pass image_digests to ingest named images, or omit it for the whole gap. The
 * per-row button passes one digest so it queues what it points at rather than
 * quietly queueing the cluster.
 *
 * Repeat runs are free — scan jobs are keyed on (registry, digest) — so the
 * button is safe to press twice.
 */
export function useIngestUnknown() {
    const queryClient = useQueryClient();
    return createMutation(() => ({
        mutationFn: ({ id, imageDigests }: { id: string; imageDigests?: string[] }) =>
            unwrap(
                client.POST("/api/v1/clusters/{id}/ingest-unknown", {
                    params: { path: { id } },
                    body: imageDigests === undefined ? {} : { image_digests: imageDigests },
                }),
            ),
        // Queueing does not scan: the gap list, the workload states and the
        // coverage counts all stay as they were until a worker finishes. They
        // are invalidated anyway so a run that raced a completed scan shows the
        // new state rather than a stale one.
        onSuccess: (_data, vars) => {
            void queryClient.invalidateQueries({ queryKey: ["clusters", vars.id] });
            void queryClient.invalidateQueries({ queryKey: ["jobs"] });
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
