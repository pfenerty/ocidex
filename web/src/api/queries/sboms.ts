import type { Accessor } from "solid-js";
import { createQuery, createInfiniteQuery } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";
import type { ComponentSummary, paths } from "~/api/client";
import type { SortDir } from "~/components/DataTable";
import type { VulnSeverityFilter } from "./clusters";

/** List SBOMs with optional filters and keyset (cursor) pagination. */
export function useSBOMs(
    params: Accessor<{
        limit?: number;
        cursor?: string;
        serial_number?: string;
        digest?: string;
    }>,
) {
    return createQuery(() => {
        const p = params();
        return {
            queryKey: [
                "sboms",
                p.serial_number,
                p.digest,
                p.limit,
                p.cursor,
            ] as const,
            queryFn: () =>
                unwrap(
                    client.GET("/api/v1/sboms", {
                        params: { query: p },
                    }),
                ),
            keepPreviousData: true,
            select: (resp) => ({ ...resp, data: resp.data ?? [] }),
        };
    });
}

/** Get a single SBOM by ID. Pass include="raw" to include rawBom. */
export function useSBOM(
    id: Accessor<string>,
    options?: { include?: Accessor<string | undefined> },
) {
    return createQuery(() => ({
        queryKey: ["sbom", id(), options?.include?.()] as const,
        queryFn: () =>
            unwrap(
                client.GET("/api/v1/sboms/{id}", {
                    params: {
                        path: { id: id() },
                        query: { include: options?.include?.() },
                    },
                }),
            ),
    }));
}

/** List components belonging to an SBOM with load-more pagination.
 *  Pages accumulate in data.pages; flatten with sbomComponents().
 *
 *  The server pages this keyset by default and by offset under sort=severity,
 *  but both travel in the same opaque cursor, so nothing here has to know which
 *  (ADR-043 rule 1 — see the ListSBOMComponentsPage query comment). The sort is
 *  in the query key, so changing it restarts the accumulation rather than
 *  appending a differently-ordered page to the one already loaded. */
export function useSBOMComponents(
    id: Accessor<string>,
    params?: Accessor<{ sort?: "severity"; dir?: "asc" | "desc" }>,
) {
    return createInfiniteQuery(() => {
        const p = params?.() ?? {};
        return {
            queryKey: ["sbom", id(), "components", p.sort, p.dir] as const,
            queryFn: ({ pageParam }: { pageParam: string }) =>
                unwrap(
                    client.GET("/api/v1/sboms/{id}/components", {
                        params: {
                            path: { id: id() },
                            query: {
                                limit: 200,
                                cursor: pageParam !== "" ? pageParam : undefined,
                                sort: p.sort,
                                dir: p.dir,
                            },
                        },
                    }),
                ),
            initialPageParam: "",
            getNextPageParam: (last: { pagination?: { hasMore?: boolean; nextCursor?: string | null } }) =>
                last.pagination?.hasMore === true ? (last.pagination.nextCursor ?? undefined) : undefined,
        };
    });
}

/** Flatten the accumulated component pages from useSBOMComponents. */
export function sbomComponents(
    pages: { components?: ComponentSummary[] | null }[] | undefined,
): ComponentSummary[] {
    return (pages ?? []).flatMap((p) => p.components ?? []);
}

/** List provenance drift history for an SBOM, newest first. */
export function useSBOMDriftHistory(
    id: Accessor<string>,
    params?: Accessor<{ limit?: number; cursor?: string }>,
    options?: { enabled?: Accessor<boolean> },
) {
    return createQuery(() => {
        const p = params?.() ?? {};
        return {
            queryKey: ["sbom", id(), "drift", p.limit, p.cursor] as const,
            queryFn: () =>
                unwrap(
                    client.GET("/api/v1/sboms/{id}/drift", {
                        params: { path: { id: id() }, query: p },
                    }),
                ),
            enabled: options?.enabled?.() ?? true,
            select: (resp) => ({ ...resp, data: resp.data ?? [] }),
        };
    });
}

/** Get the dependency graph for an SBOM. */
export function useSBOMDependencies(
    id: Accessor<string>,
    options?: { enabled?: Accessor<boolean> },
) {
    return createQuery(() => ({
        queryKey: ["sbom", id(), "dependencies"] as const,
        queryFn: () =>
            unwrap(
                client.GET("/api/v1/sboms/{id}/dependencies", {
                    params: { path: { id: id() } },
                }),
            ),
        enabled: options?.enabled?.() ?? true,
        select: (resp) => ({
            ...resp,
            edges: resp.edges ?? [],
            nodes: resp.nodes ?? [],
        }),
    }));
}

/** The columns the API will order an SBOM's vulnerability list by. */
export type SBOMVulnSortKey =
    NonNullable<paths["/api/v1/sboms/{id}/vulns"]["get"]["parameters"]["query"]>["sort"];

export interface SBOMVulnQueryParams {
    severity?: VulnSeverityFilter;
    sort?: SBOMVulnSortKey;
    dir?: SortDir;
    limit?: number;
    offset?: number;
}

/**
 * useSBOMVulns — the findings inside one SBOM, keyed by canonical id server-side
 * so an advisory published under several ids (GO-…, GHSA-…, CVE-…) is one row
 * carrying the whole alias group's package count.
 *
 * That keying is what lets this list agree with the vulnSummary tile above it;
 * a client-side fan-out over components could not, because it would count the
 * same advisory once per id and once per package.
 */
export function useSBOMVulns(
    id: Accessor<string>,
    params?: Accessor<SBOMVulnQueryParams>,
    options?: { enabled?: Accessor<boolean> },
) {
    return createQuery(() => {
        const p = params?.() ?? {};
        return {
            queryKey: ["sbom", id(), "vulns", p.severity, p.sort, p.dir, p.limit, p.offset] as const,
            queryFn: () =>
                unwrap(
                    client.GET("/api/v1/sboms/{id}/vulns", {
                        params: { path: { id: id() }, query: p },
                    }),
                ),
            enabled: options?.enabled?.() ?? true,
            select: (resp) => ({ ...resp, data: resp.data ?? [] }),
        };
    });
}
