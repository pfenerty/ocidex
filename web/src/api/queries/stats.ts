import { createQuery } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";

// While the server reports `warming` it has no snapshot yet and every count in
// the payload is a zero placeholder. The real numbers are computed out of band
// by the background warmer, so poll until one arrives instead of leaving the
// page on a permanent skeleton.
const WARMING_POLL_MS = 15_000;

export function useDashboardStats() {
    return createQuery(() => ({
        queryKey: ["stats", "summary"] as const,
        queryFn: () => unwrap(client.GET("/api/v1/stats", {})),
        staleTime: 60_000,
        refetchInterval: (query) => (query.state.data?.warming === true ? WARMING_POLL_MS : false),
    }));
}
