import { createQuery } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";
import type { Accessor } from "solid-js";

/** Query params for the licenses list endpoint. */
export interface UseLicensesParams {
    limit?: number;
    offset?: number;
    name?: string;
    spdx_id?: string;
    category?: string;
}

/** Paginated list of licenses. GET /api/v1/licenses */
export function useLicenses(params: Accessor<UseLicensesParams>) {
    return createQuery(() => {
        const p = params();
        return {
            queryKey: [
                "licenses",
                p.name,
                p.spdx_id,
                p.category,
                p.limit,
                p.offset,
            ] as const,
            queryFn: () =>
                unwrap(
                    client.GET("/api/v1/licenses", {
                        params: { query: p },
                    }),
                ),
            keepPreviousData: true,
            select: (resp) => ({ ...resp, data: resp.data ?? [] }),
        };
    });
}

/** Query params for the license components endpoint. */
export interface UseLicenseComponentsParams {
    limit?: number;
    offset?: number;
}

/** Paginated list of components for a given license. GET /api/v1/licenses/{id}/components */
export function useLicenseComponents(
    id: Accessor<string>,
    params: Accessor<UseLicenseComponentsParams>,
) {
    return createQuery(() => {
        const p = params();
        return {
            queryKey: [
                "licenses",
                id(),
                "components",
                p.limit,
                p.offset,
            ] as const,
            queryFn: () =>
                unwrap(
                    client.GET("/api/v1/licenses/{id}/components", {
                        params: {
                            path: { id: id() },
                            query: p,
                        },
                    }),
                ),
            keepPreviousData: true,
            select: (resp) => ({ ...resp, data: resp.data ?? [] }),
        };
    });
}
