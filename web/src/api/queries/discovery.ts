import { createQuery } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";
import type { paths } from "~/types/openapi";

// The server computes the discovery aggregates out of band. Until the first
// snapshot lands it answers 200 with `warming` and four empty sections — which
// is not the same as an empty catalog — so poll until a real one arrives rather
// than rendering "nothing here" over a catalog that is still being measured.
const WARMING_POLL_MS = 15_000;

type DiscoveryResponse =
    paths["/api/v1/discover"]["get"]["responses"][200]["content"]["application/json"];

export type DiscoverArtifact = NonNullable<DiscoveryResponse["top_artifacts"]>[number];
export type DiscoverRecent = NonNullable<DiscoveryResponse["recent_artifacts"]>[number];
export type DiscoverVuln = NonNullable<DiscoveryResponse["top_vulnerabilities"]>[number];
export type DiscoverLicense = NonNullable<DiscoveryResponse["license_spread"]>[number];

/**
 * useDiscovery reads the public landing-page aggregates.
 *
 * The response is identical for every caller — the endpoint takes no viewer
 * parameter — so it is cached long and shared across mounts rather than refetched
 * per visit.
 */
export function useDiscovery() {
    return createQuery(() => ({
        queryKey: ["discover"] as const,
        queryFn: () => unwrap(client.GET("/api/v1/discover", {})),
        staleTime: 60_000,
        refetchInterval: (query) => (query.state.data?.warming === true ? WARMING_POLL_MS : false),
    }));
}
