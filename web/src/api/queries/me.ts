import { createQuery } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";

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
export function useMyNamespaces() {
    return createQuery(() => ({
        queryKey: ["me", "namespaces"] as const,
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
export function useMyActivity() {
    return createQuery(() => ({
        queryKey: ["me", "activity"] as const,
        queryFn: () => unwrap(client.GET("/api/v1/users/me/activity")),
        select: (resp) => ({ ...resp, data: resp.data ?? [] }),
    }));
}

/** useMyDriftFeed — provenance drift on artifacts in namespaces the caller owns. */
export function useMyDriftFeed() {
    return createQuery(() => ({
        queryKey: ["me", "drift-feed"] as const,
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
export function useMyClusters() {
    return createQuery(() => ({
        queryKey: ["me", "clusters"] as const,
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
export function useMyVulnerabilities(limit = 5) {
    return createQuery(() => ({
        queryKey: ["me", "vulns", limit] as const,
        queryFn: () =>
            unwrap(client.GET("/api/v1/users/me/vulns", { params: { query: { limit } } })),
        select: (resp) => ({ ...resp, data: resp.data ?? [] }),
    }));
}
