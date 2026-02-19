import type { Accessor } from "solid-js";
import { createQuery } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";

/** List SBOMs with optional filters and pagination. */
export function useSBOMs(
    params: Accessor<{
        limit?: number;
        offset?: number;
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
                p.offset,
            ] as const,
            queryFn: () =>
                unwrap(
                    client.GET("/api/v1/sbom", {
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
                client.GET("/api/v1/sbom/{id}", {
                    params: {
                        path: { id: id() },
                        query: { include: options?.include?.() },
                    },
                }),
            ),
    }));
}

/** List components belonging to an SBOM. */
export function useSBOMComponents(id: Accessor<string>) {
    return createQuery(() => ({
        queryKey: ["sbom", id(), "components"] as const,
        queryFn: () =>
            unwrap(
                client.GET("/api/v1/sbom/{id}/components", {
                    params: { path: { id: id() } },
                }),
            ),
        select: (resp) => ({ ...resp, components: resp.components ?? [] }),
    }));
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
                client.GET("/api/v1/sbom/{id}/dependencies", {
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
