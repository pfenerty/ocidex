import { createQuery } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";

/** useServerVersion — GET /api/v1/: the running build and its vulnerability database's age. */
export function useServerVersion() {
    return createQuery(() => ({
        queryKey: ["server-version"] as const,
        queryFn: () => unwrap(client.GET("/api/v1/")),
        staleTime: 5 * 60 * 1000,
    }));
}
