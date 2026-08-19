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
    limit?: number;
    offset?: number;
}

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
