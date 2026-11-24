import type { Accessor } from "solid-js";
import { createQuery } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";
import { selfScopedEnabled, type SelfScopedOptions } from "./selfScoped";

// ---------------------------------------------------------------------------
// Self-scoped collections (ocidex-998g.2 / .5)
//
// Every hook here reads a /api/v1/users/me/* endpoint, which is why none of
// them takes a user argument: the caller is the session, never a parameter.
// They are grouped in one module rather than filed next to their public
// siblings because the dashboard mounts them together, and a reader asking
// "what does the workspace actually load" should find one file, not six.
//
// The queries are keyed under a shared "me" prefix so signing out can drop the
// whole workspace with a single invalidation.
// ---------------------------------------------------------------------------

/** useMyNamespaces — namespaces the caller owns. */
export function useMyNamespaces(opts?: SelfScopedOptions) {
    return createQuery(() => ({
        queryKey: ["me", "namespaces"] as const,
        enabled: selfScopedEnabled(opts),
        queryFn: () => unwrap(client.GET("/api/v1/users/me/namespaces")),
        select: (resp) => ({ ...resp, data: resp.data ?? [] }),
    }));
}

/**
 * useMyActivity — SBOMs ingested into the caller's namespaces, newest first.
 *
 * This backs the ingest-health panel: "health" here is literally the shape of
 * the recent ingest stream, so the panel reads the same rows the activity feed
 * would show rather than a separate summary that could disagree with it.
 */
export function useMyActivity(opts?: SelfScopedOptions) {
    return createQuery(() => ({
        queryKey: ["me", "activity"] as const,
        enabled: selfScopedEnabled(opts),
        queryFn: () => unwrap(client.GET("/api/v1/users/me/activity")),
        select: (resp) => ({ ...resp, data: resp.data ?? [] }),
    }));
}

/** useMyDriftFeed — provenance drift on artifacts in namespaces the caller owns. */
export function useMyDriftFeed(opts?: SelfScopedOptions) {
    return createQuery(() => ({
        queryKey: ["me", "drift-feed"] as const,
        enabled: selfScopedEnabled(opts),
        queryFn: () => unwrap(client.GET("/api/v1/users/me/drift-feed")),
        select: (resp) => ({ ...resp, data: resp.data ?? [] }),
    }));
}

/**
 * useMyClusters — clusters in namespaces the caller owns (ADR-044).
 *
 * Separate from useListClusters, which is visibility-scoped and so also returns
 * other people's public clusters: the workspace panel is meant to be the
 * caller's own fleet, and a stale cluster someone else owns is not their
 * problem to act on.
 */
export function useMyClusters(opts?: SelfScopedOptions) {
    return createQuery(() => ({
        queryKey: ["me", "clusters"] as const,
        enabled: selfScopedEnabled(opts),
        queryFn: () => unwrap(client.GET("/api/v1/users/me/clusters")),
        select: (resp) => ({ ...resp, data: resp.data ?? [] }),
    }));
}

/**
 * useMyVulnerabilities — vulnerabilities ranked by exposure across owned
 * namespaces. Distinct from useTopVulnerabilities, which is catalog-wide: the
 * dashboard figure is meant to be the caller's own backlog, and other people's
 * public artifacts would inflate it with work nobody expects them to do.
 */
export function useMyVulnerabilities(limit = 5, opts?: SelfScopedOptions) {
    return createQuery(() => ({
        queryKey: ["me", "vulns", limit] as const,
        enabled: selfScopedEnabled(opts),
        queryFn: () =>
            unwrap(client.GET("/api/v1/users/me/vulns", { params: { query: { limit } } })),
        select: (resp) => ({ ...resp, data: resp.data ?? [] }),
    }));
}

/**
 * useMyMoves — the caller's upgrade queue: per running image, the tag that
 * removes the most criticals and how long a better tag has been out, plus the
 * criticals left after every upgrade and the same totals by namespace.
 */
export function useMyMoves(opts?: SelfScopedOptions) {
    return createQuery(() => ({
        queryKey: ["me", "moves"] as const,
        enabled: selfScopedEnabled(opts),
        queryFn: () => unwrap(client.GET("/api/v1/users/me/moves")),
        // The API sends empty lists as null; the page should not have to care.
        select: (m) => ({
            ...m,
            upgrades: (m.upgrades ?? []).map((u) => ({ ...u, namespaces: u.namespaces ?? [] })),
            leftoverCriticals: (m.leftoverCriticals ?? []).map((l) => ({ ...l, images: l.images ?? [] })),
            namespaces: m.namespaces ?? [],
        }),
    }));
}

/** A running image with no SBOM in one of the caller's clusters. */
export interface SeenOnlyImage {
    clusterId: string;
    imageRef: string;
    imageDigest: string;
}

/**
 * useMySeenOnlyImages — running images with no SBOM across the caller's own
 * clusters, for the silhouettes in the Artifacts grid. One request per
 * cluster, issued together; deduplicated by digest, since one image commonly
 * runs on several clusters.
 */
export function useMySeenOnlyImages(clusterIds: Accessor<string[]>, opts?: SelfScopedOptions) {
    return createQuery(() => ({
        queryKey: ["me", "seen-only-images", clusterIds()] as const,
        enabled: selfScopedEnabled(opts) && clusterIds().length > 0,
        queryFn: async (): Promise<SeenOnlyImage[]> => {
            const pages = await Promise.all(
                clusterIds().map(async (id) => {
                    const resp = await unwrap(
                        client.GET("/api/v1/clusters/{id}/unknown-images", {
                            params: { path: { id }, query: { limit: 100 } },
                        }),
                    );
                    return (resp.data ?? []).map((u) => ({
                        clusterId: id,
                        imageRef: u.imageRef,
                        imageDigest: u.imageDigest,
                    }));
                }),
            );
            const seen = new Map<string, SeenOnlyImage>();
            for (const img of pages.flat()) if (!seen.has(img.imageDigest)) seen.set(img.imageDigest, img);
            return [...seen.values()];
        },
    }));
}
