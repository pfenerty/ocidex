import { createQuery } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";
import type { Accessor } from "solid-js";

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

export function useTopVulnerabilities(
    params: Accessor<{ limit?: number; offset?: number; severity?: string }>,
) {
    return createQuery(() => {
        const p = params();
        return {
            queryKey: ["vulns", "top", p.severity, p.limit, p.offset] as const,
            queryFn: () =>
                unwrap(
                    client.GET("/api/v1/vulns", {
                        params: {
                            query: {
                                limit: p.limit,
                                offset: p.offset,
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
