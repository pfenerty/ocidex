import type { Accessor } from "solid-js";
import { createQuery, createInfiniteQuery } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";
import type { ComponentSummary } from "~/api/client";

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

/** List components belonging to an SBOM with keyset (load-more) pagination.
 *  Pages accumulate in data.pages; flatten with sbomComponents(). */
export function useSBOMComponents(id: Accessor<string>) {
    return createInfiniteQuery(() => ({
        queryKey: ["sbom", id(), "components"] as const,
        queryFn: ({ pageParam }: { pageParam: string }) =>
            unwrap(
                client.GET("/api/v1/sboms/{id}/components", {
                    params: {
                        path: { id: id() },
                        query: { limit: 200, cursor: pageParam !== "" ? pageParam : undefined },
                    },
                }),
            ),
        initialPageParam: "",
        getNextPageParam: (last: { pagination?: { hasMore?: boolean; nextCursor?: string | null } }) =>
            last.pagination?.hasMore === true ? (last.pagination.nextCursor ?? undefined) : undefined,
    }));
}

/** Flatten the accumulated component pages from useSBOMComponents. */
export function sbomComponents(
    pages: { components?: ComponentSummary[] | null }[] | undefined,
): ComponentSummary[] {
    return (pages ?? []).flatMap((p) => p.components ?? []);
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
