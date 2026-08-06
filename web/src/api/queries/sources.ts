import type { Accessor } from "solid-js";
import { createQuery } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";

/** Ingest channels visible to the caller (ADR-039). A source of kind
 *  `oci_registry` shares its id with the `registry` row that carries the OCI
 *  configuration, so the two lists join on `id` without a second lookup. */
export function useListSources(params?: Accessor<{ namespace_id?: string }>) {
    return createQuery(() => {
        const p = params?.() ?? {};
        return {
            queryKey: ["sources", p.namespace_id] as const,
            queryFn: () =>
                unwrap(client.GET("/api/v1/sources", { params: { query: p } })),
            select: (resp) => ({ ...resp, data: resp.data ?? [] }),
        };
    });
}
