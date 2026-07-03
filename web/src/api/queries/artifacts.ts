import { createMemo, type Accessor } from "solid-js";
import { createQuery, createInfiniteQuery } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";
import type { ArtifactSummary } from "~/api/client";

// ---------------------------------------------------------------------------
// useArtifacts — GET /api/v1/artifacts
// ---------------------------------------------------------------------------

export interface UseArtifactsParams {
    limit?: number;
    name?: string;
    type?: string;
    sufficient?: boolean;
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
            queryKey: ["artifacts-infinite", p.name, p.type, p.limit, p.sufficient] as const,
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

export interface UseArtifactVersionsParams {
    limit?: number;
    offset?: number;
}

export function useArtifactVersions(
    id: Accessor<string>,
    params: Accessor<UseArtifactVersionsParams>,
    options?: { enabled?: Accessor<boolean> },
) {
    return createQuery(() => {
        const p = params();
        return {
            queryKey: ["artifact", id(), "versions", p.limit, p.offset] as const,
            queryFn: () =>
                unwrap(
                    client.GET("/api/v1/artifacts/{id}/versions", {
                        params: {
                            path: { id: id() },
                            query: { limit: p.limit, offset: p.offset },
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
    },
) {
    return createQuery(() => ({
        queryKey: ["artifact", id(), "changelog", options?.arch?.(), options?.flavor?.()] as const,
        queryFn: () => {
            const arch = options?.arch?.();
            const flavor = options?.flavor?.();
            return unwrap(
                client.GET("/api/v1/artifacts/{id}/changelog", {
                    params: {
                        path: { id: id() },
                        query: {
                            arch: arch !== "" ? arch : undefined,
                            flavor: flavor !== "" ? flavor : undefined,
                        },
                    },
                }),
            );
        },
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
