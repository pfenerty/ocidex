import { createQuery } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";

export function useDashboardStats() {
    return createQuery(() => ({
        queryKey: ["stats", "summary"] as const,
        queryFn: () => unwrap(client.GET("/api/v1/stats", {})),
        staleTime: 60_000,
    }));
}
