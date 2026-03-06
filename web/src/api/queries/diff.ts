import type { Accessor } from "solid-js";
import { createQuery } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";

/**
 * Diff two SBOMs by their IDs.
 */
export function useDiff(params: Accessor<{ from?: string; to?: string }>) {
    return createQuery(() => {
        const p = params();
        return {
            queryKey: ["diff", p.from, p.to] as const,
            queryFn: () =>
                unwrap(
                    client.GET("/api/v1/sboms/diff", {
                        params: { query: { from: p.from ?? "", to: p.to ?? "" } },
                    }),
                ),
            enabled: p.from !== undefined && p.to !== undefined,
            select: (resp) => ({ ...resp, changes: resp.changes ?? [] }),
        };
    });
}
