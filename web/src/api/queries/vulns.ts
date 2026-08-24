import { createQuery } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";
import type { Accessor } from "solid-js";
import type { paths } from "~/types/openapi";

export function useVulnerabilityDetail(
    id: Accessor<string>,
    params: Accessor<{ limit?: number; offset?: number }>,
) {
    return createQuery(() => {
        const vulnId = id();
        const p = params();
        return {
            queryKey: ["vuln", vulnId, p.limit, p.offset] as const,
            queryFn: () =>
                unwrap(
                    client.GET("/api/v1/vulns/{id}", {
                        params: {
                            path: { id: vulnId },
                            query: { limit: p.limit, offset: p.offset },
                        },
                    }),
                ),
            enabled: !!vulnId,
            keepPreviousData: true,
        };
    });
}

// The sort field is an enum in the spec, so the union is the contract: adding a
// sortable column here means adding it to ListTopVulnerabilitiesInput too.
export type TopVulnSort = NonNullable<
    NonNullable<
        paths["/api/v1/vulns"]["get"]["parameters"]["query"]
    >["sort"]
>;

export function useTopVulnerabilities(
    params: Accessor<{
        limit?: number;
        offset?: number;
        q?: string;
        severity?: string;
        sort?: TopVulnSort;
        sort_dir?: "asc" | "desc";
    }>,
) {
    return createQuery(() => {
        const p = params();
        return {
            queryKey: [
                "vulns",
                "top",
                p.q,
                p.severity,
                p.sort,
                p.sort_dir,
                p.limit,
                p.offset,
            ] as const,
            queryFn: () =>
                unwrap(
                    client.GET("/api/v1/vulns", {
                        params: {
                            query: {
                                limit: p.limit,
                                offset: p.offset,
                                q: p.q !== "" ? p.q : undefined,
                                sort: p.sort,
                                sort_dir: p.sort_dir,
                                severity: (p.severity !== "" ? p.severity : undefined) as
                                    | "CRITICAL"
                                    | "HIGH"
                                    | "MEDIUM"
                                    | "LOW"
                                    | undefined,
                            },
                        },
                    }),
                ),
            keepPreviousData: true,
        };
    });
}
