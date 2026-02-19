import { createMemo, type Accessor } from "solid-js";
import { createQuery } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";
import type { ArtifactSummary } from "~/api/client";

// ---------------------------------------------------------------------------
// useArtifacts — GET /api/v1/artifacts
// ---------------------------------------------------------------------------

export interface UseArtifactsParams {
    limit?: number;
    offset?: number;
    name?: string;
    type?: string;
}

export function useArtifacts(params: Accessor<UseArtifactsParams>) {
    return createQuery(() => {
        const p = params();
        return {
            queryKey: ["artifacts", p.name, p.type, p.limit, p.offset] as const,
            queryFn: () =>
                unwrap(
                    client.GET("/api/v1/artifacts", {
                        params: {
                            query: {
                                limit: p.limit,
                                offset: p.offset,
                                name: p.name || undefined,
                                type: p.type || undefined,
                            },
                        },
                    }),
                ),
            keepPreviousData: true,
            select: (resp) => ({ ...resp, data: resp.data ?? [] }),
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
    offset?: number;
    subject_version?: string;
}

export function useArtifactSBOMs(
    id: Accessor<string>,
    params: Accessor<UseArtifactSBOMsParams>,
    options?: { enabled?: Accessor<boolean> },
) {
    return createQuery(() => {
        const p = params();
        return {
            queryKey: ["artifact", id(), "sboms", p.limit, p.offset] as const,
            queryFn: () =>
                unwrap(
                    client.GET("/api/v1/artifacts/{id}/sboms", {
                        params: {
                            path: { id: id() },
                            query: {
                                limit: p.limit,
                                offset: p.offset,
                                subject_version: p.subject_version || undefined,
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
    options?: { enabled?: Accessor<boolean> },
) {
    return createQuery(() => ({
        queryKey: ["artifact", id(), "changelog"] as const,
        queryFn: () =>
            unwrap(
                client.GET("/api/v1/artifacts/{id}/changelog", {
                    params: { path: { id: id() } },
                }),
            ),
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
                    params: { query: { limit: 500 } },
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

    return (id: string | undefined) => {
        if (!id) return undefined;
        return lookupMap().get(id);
    };
}
