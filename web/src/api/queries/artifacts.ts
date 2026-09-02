import { createMemo, type Accessor } from "solid-js";
import { createQuery, createInfiniteQuery } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";
import type { ArtifactSummary, paths } from "~/api/client";
import type { SortDir } from "~/components/DataTable";
import type { VulnSeverityFilter } from "./clusters";

// ---------------------------------------------------------------------------
// useArtifacts — GET /api/v1/artifacts
// ---------------------------------------------------------------------------

export interface UseArtifactsParams {
    limit?: number;
    name?: string;
    type?: string;
    sufficient?: boolean;
    /** Severity sort. Server-side: the list is paged, so sorting on the client
     *  would only reorder the rows already fetched. */
    sort?: "severity";
    dir?: "asc" | "desc";
}

/** Single-page artifact fetch (first keyset page). Used where the full bounded
 *  list is wanted without paging UI (e.g. the diff picker). */
export function useArtifacts(params: Accessor<UseArtifactsParams>) {
    return createQuery(() => {
        const p = params();
        return {
            queryKey: ["artifacts", p.name, p.type, p.limit, p.sufficient] as const,
            queryFn: () =>
                unwrap(
                    client.GET("/api/v1/artifacts", {
                        params: {
                            query: {
                                limit: p.limit,
                                name: p.name !== "" ? p.name : undefined,
                                type: p.type !== "" ? p.type : undefined,
                                sufficient: p.sufficient !== undefined ? String(p.sufficient) : undefined,
                            },
                        },
                    }),
                ),
            keepPreviousData: true,
            select: (resp) => ({ ...resp, data: resp.data ?? [] }),
        };
    });
}

/** Keyset (load-more) artifact list. Pages accumulate; follow nextCursor. */
export function useArtifactsInfinite(params: Accessor<UseArtifactsParams>) {
    return createInfiniteQuery(() => {
        const p = params();
        return {
            queryKey: ["artifacts-infinite", p.name, p.type, p.limit, p.sufficient, p.sort, p.dir] as const,
            queryFn: ({ pageParam }: { pageParam: string }) =>
                unwrap(
                    client.GET("/api/v1/artifacts", {
                        params: {
                            query: {
                                limit: p.limit,
                                cursor: pageParam !== "" ? pageParam : undefined,
                                name: p.name !== "" ? p.name : undefined,
                                type: p.type !== "" ? p.type : undefined,
                                sufficient: p.sufficient !== undefined ? String(p.sufficient) : undefined,
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

// ---------------------------------------------------------------------------
// useArtifact — GET /api/v1/artifacts/{id}
// ---------------------------------------------------------------------------

export function useArtifact(id: Accessor<string>) {
    return createQuery(() => ({
        queryKey: ["artifact", id()] as const,
        queryFn: () =>
            unwrap(
                client.GET("/api/v1/artifacts/{id}", {
                    params: { path: { id: id() } },
                }),
            ),
    }));
}

// ---------------------------------------------------------------------------
// useArtifactSBOMs — GET /api/v1/artifacts/{id}/sboms
// ---------------------------------------------------------------------------

export interface UseArtifactSBOMsParams {
    limit?: number;
    subject_version?: string;
    image_version?: string;
}

/** First keyset page of an artifact's SBOMs. Consumers (diff picker, version
 *  history, arch siblings) want a single bounded page, so no cursor is paged. */
export function useArtifactSBOMs(
    id: Accessor<string>,
    params: Accessor<UseArtifactSBOMsParams>,
    options?: { enabled?: Accessor<boolean> },
) {
    return createQuery(() => {
        const p = params();
        return {
            queryKey: [
                "artifact",
                id(),
                "sboms",
                p.subject_version,
                p.image_version,
                p.limit,
            ] as const,
            queryFn: () =>
                unwrap(
                    client.GET("/api/v1/artifacts/{id}/sboms", {
                        params: {
                            path: { id: id() },
                            query: {
                                limit: p.limit,
                                subject_version: p.subject_version !== "" ? p.subject_version : undefined,
                                image_version: p.image_version !== "" ? p.image_version : undefined,
                            },
                        },
                    }),
                ),
            keepPreviousData: true,
            enabled: options?.enabled?.() ?? true,
            select: (resp) => ({ ...resp, data: resp.data ?? [] }),
        };
    });
}

// ---------------------------------------------------------------------------
// useArtifactVersions — GET /api/v1/artifacts/{id}/versions
// ---------------------------------------------------------------------------

export type VersionSortMode = "semver" | "all";

export interface UseArtifactVersionsParams {
    limit?: number;
    offset?: number;
    mode?: VersionSortMode;
    /** Column ordering layered on top of `mode`, which also filters. */
    sort?: "severity";
    dir?: "asc" | "desc";
}

export function useArtifactVersions(
    id: Accessor<string>,
    params: Accessor<UseArtifactVersionsParams>,
    options?: { enabled?: Accessor<boolean> },
) {
    return createQuery(() => {
        const p = params();
        return {
            queryKey: [
                "artifact",
                id(),
                "versions",
                p.limit,
                p.offset,
                p.mode,
                p.sort,
                p.dir,
            ] as const,
            queryFn: () =>
                unwrap(
                    client.GET("/api/v1/artifacts/{id}/versions", {
                        params: {
                            path: { id: id() },
                            query: {
                                limit: p.limit,
                                offset: p.offset,
                                mode: p.mode,
                                sort: p.sort,
                                dir: p.dir,
                            },
                        },
                    }),
                ),
            keepPreviousData: true,
            enabled: options?.enabled?.() ?? true,
            select: (resp) => ({ ...resp, data: resp.data ?? [] }),
        };
    });
}

// ---------------------------------------------------------------------------
// useArtifactChangelog — GET /api/v1/artifacts/{id}/changelog
// ---------------------------------------------------------------------------

export function useArtifactChangelog(
    id: Accessor<string>,
    options?: {
        enabled?: Accessor<boolean>;
        arch?: Accessor<string | undefined>;
        flavor?: Accessor<string | undefined>;
        mode?: Accessor<VersionSortMode | undefined>;
        limit?: Accessor<number | undefined>;
        offset?: Accessor<number | undefined>;
    },
) {
    return createQuery(() => ({
        queryKey: [
            "artifact",
            id(),
            "changelog",
            options?.arch?.(),
            options?.flavor?.(),
            options?.mode?.(),
            options?.limit?.(),
            options?.offset?.(),
        ] as const,
        queryFn: () => {
            const arch = options?.arch?.();
            const flavor = options?.flavor?.();
            const mode = options?.mode?.();
            return unwrap(
                client.GET("/api/v1/artifacts/{id}/changelog", {
                    params: {
                        path: { id: id() },
                        query: {
                            arch: arch !== "" ? arch : undefined,
                            flavor: flavor !== "" ? flavor : undefined,
                            mode,
                            limit: options?.limit?.(),
                            offset: options?.offset?.(),
                        },
                    },
                }),
            );
        },
        keepPreviousData: true,
        enabled: options?.enabled?.() ?? true,
        select: (resp) => ({
            ...resp,
            entries: (resp.entries ?? []).map((e) => ({
                ...e,
                changes: e.changes ?? [],
            })),
        }),
    }));
}

// ---------------------------------------------------------------------------
// useArtifactLicenseSummary — GET /api/v1/artifacts/{id}/license-summary
// ---------------------------------------------------------------------------

export function useArtifactLicenseSummary(
    id: Accessor<string>,
    options?: { enabled?: Accessor<boolean> },
) {
    return createQuery(() => ({
        queryKey: ["artifact", id(), "license-summary"] as const,
        queryFn: () =>
            unwrap(
                client.GET("/api/v1/artifacts/{id}/license-summary", {
                    params: { path: { id: id() } },
                }),
            ),
        enabled: options?.enabled?.() ?? true,
        select: (resp) => ({ ...resp, licenses: resp.licenses ?? [] }),
    }));
}

// ---------------------------------------------------------------------------
// useArtifactUsages — GET /api/v1/artifacts/{id}/usages
// useArtifactContains — GET /api/v1/artifacts/{id}/contains
// ---------------------------------------------------------------------------

/** Artifacts whose latest SBOM contains a component matching this artifact
 *  ("ocidex v1.2.3 ships in these images" — ADR-041). */
export function useArtifactUsages(
    id: Accessor<string>,
    options?: { enabled?: Accessor<boolean> },
) {
    return createQuery(() => ({
        queryKey: ["artifact", id(), "usages"] as const,
        queryFn: () =>
            unwrap(
                client.GET("/api/v1/artifacts/{id}/usages", {
                    params: { path: { id: id() } },
                }),
            ),
        enabled: options?.enabled?.() ?? true,
        select: (resp) => ({ ...resp, usages: resp.usages ?? [] }),
    }));
}

/** Tracked artifacts appearing as components of this artifact's latest SBOM
 *  (the inverse direction of useArtifactUsages). */
export function useArtifactContains(
    id: Accessor<string>,
    options?: { enabled?: Accessor<boolean> },
) {
    return createQuery(() => ({
        queryKey: ["artifact", id(), "contains"] as const,
        queryFn: () =>
            unwrap(
                client.GET("/api/v1/artifacts/{id}/contains", {
                    params: { path: { id: id() } },
                }),
            ),
        enabled: options?.enabled?.() ?? true,
        select: (resp) => ({ ...resp, contains: resp.contains ?? [] }),
    }));
}

// ---------------------------------------------------------------------------
// useArtifactVulnSummary — GET /api/v1/artifacts/{id}/vuln-summary
// ---------------------------------------------------------------------------

export function useArtifactVulnSummary(id: Accessor<string>) {
    return createQuery(() => ({
        queryKey: ["artifact", id(), "vuln-summary"] as const,
        queryFn: () =>
            unwrap(
                client.GET("/api/v1/artifacts/{id}/vuln-summary", {
                    params: { path: { id: id() } },
                }),
            ),
    }));
}

// ---------------------------------------------------------------------------
// useArtifactVulns — GET /api/v1/artifacts/{id}/vulns
// ---------------------------------------------------------------------------

export type ArtifactVulnSortKey =
    NonNullable<paths["/api/v1/artifacts/{id}/vulns"]["get"]["parameters"]["query"]>["sort"];

export interface ArtifactVulnQueryParams {
    severity?: VulnSeverityFilter;
    /** Pre-filter to one advisory, by canonical or native id. This is the
     *  parameter /vulnerabilities/:id links with. */
    vuln?: string;
    sort?: ArtifactVulnSortKey;
    dir?: SortDir;
    limit?: number;
    offset?: number;
}

/**
 * useArtifactVulns — the findings across an artifact's versions.
 *
 * Wider than useArtifactVulnSummary, which counts the newest SBOM only: this
 * covers the newest SBOM *per version*, because the question it exists to
 * answer is which versions carry a finding. The two therefore disagree by
 * design, and the tab says so.
 */
export function useArtifactVulns(
    id: Accessor<string>,
    params?: Accessor<ArtifactVulnQueryParams>,
    options?: { enabled?: Accessor<boolean> },
) {
    return createQuery(() => {
        const p = params?.() ?? {};
        return {
            queryKey: ["artifact", id(), "vulns", p.severity, p.vuln, p.sort, p.dir, p.limit, p.offset] as const,
            queryFn: () =>
                unwrap(
                    client.GET("/api/v1/artifacts/{id}/vulns", {
                        params: { path: { id: id() }, query: p },
                    }),
                ),
            enabled: options?.enabled?.() ?? true,
            select: (resp) => ({ ...resp, data: resp.data ?? [] }),
        };
    });
}

// ---------------------------------------------------------------------------
// useArtifactNames — bulk-fetch artifacts for ID → artifact lookup
// ---------------------------------------------------------------------------

export function useArtifactNames(): (
    id: string | undefined,
) => ArtifactSummary | undefined {
    const query = createQuery(() => ({
        queryKey: ["artifacts", "name-lookup"] as const,
        queryFn: () =>
            unwrap(
                client.GET("/api/v1/artifacts", {
                    params: { query: { limit: 200 } },
                }),
            ),
        staleTime: 60_000,
        select: (resp) => ({ ...resp, data: resp.data ?? [] }),
    }));

    const lookupMap = createMemo(() => {
        const map = new Map<string, ArtifactSummary>();
        if (query.data) {
            for (const a of query.data.data) {
                map.set(a.id, a);
            }
        }
        return map;
    });

    // eslint-disable-next-line solid/reactivity
    return (id: string | undefined) => {
        if (id === undefined) return undefined;
        return lookupMap().get(id);
    };
}
