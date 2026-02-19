import { createQuery } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";
import type { Accessor } from "solid-js";

/** Parameters for searching distinct components. */
export interface DistinctComponentParams {
    limit?: number;
    offset?: number;
    name?: string;
    group?: string;
    type?: string;
    purl_type?: string;
    sort?: string;
    sort_dir?: string;
}

/** Parameters for fetching component version history. */
export interface ComponentVersionParams {
    name: string;
    group?: string;
    version?: string;
    type?: string;
}

/** Search distinct components (deduplicated by name+group). */
export function useDistinctComponents(
    params: Accessor<DistinctComponentParams>,
) {
    return createQuery(() => {
        const p = params();
        return {
            queryKey: [
                "components-distinct",
                p.name,
                p.group,
                p.type,
                p.purl_type,
                p.sort,
                p.sort_dir,
                p.limit,
                p.offset,
            ] as const,
            queryFn: () =>
                unwrap(
                    client.GET("/api/v1/components/distinct", {
                        params: {
                            query: {
                                name: p.name || undefined,
                                group: p.group || undefined,
                                type: p.type || undefined,
                                purl_type: p.purl_type || undefined,
                                sort: p.sort,
                                sort_dir: p.sort_dir,
                                limit: p.limit,
                                offset: p.offset,
                            },
                        },
                    }),
                ),
            keepPreviousData: true,
            select: (resp) => ({
                ...resp,
                data: (resp.data ?? []).map((c) => ({
                    ...c,
                    purlTypes: c.purlTypes ?? [],
                })),
            }),
        };
    });
}

/** List all known purl type strings (e.g. "npm", "golang", "maven"). */
export function useComponentPurlTypes() {
    return createQuery(() => ({
        queryKey: ["component-purl-types"] as const,
        queryFn: () => unwrap(client.GET("/api/v1/components/purl-types")),
        staleTime: 60_000,
        select: (resp) => ({ ...resp, types: resp.types ?? [] }),
    }));
}

/** Get a single component by ID. */
export function useComponent(id: Accessor<string>) {
    return createQuery(() => ({
        queryKey: ["component", id()] as const,
        queryFn: () =>
            unwrap(
                client.GET("/api/v1/components/{id}", {
                    params: { path: { id: id() } },
                }),
            ),
    }));
}

/** Get the version history for a component by name/group/version/type. */
export function useComponentVersions(
    params: Accessor<ComponentVersionParams | undefined>,
    options?: { enabled?: Accessor<boolean> },
) {
    return createQuery(() => {
        const p = params();
        return {
            queryKey: [
                "component-versions",
                p?.name,
                p?.group,
                p?.version,
                p?.type,
            ] as const,
            queryFn: () =>
                unwrap(
                    client.GET("/api/v1/components/versions", {
                        params: {
                            query: {
                                name: p!.name,
                                group: p!.group || undefined,
                                version: p!.version || undefined,
                                type: p!.type || undefined,
                            },
                        },
                    }),
                ),
            enabled: options?.enabled?.() ?? !!p?.name,
            select: (resp) => ({ ...resp, versions: resp.versions ?? [] }),
        };
    });
}
