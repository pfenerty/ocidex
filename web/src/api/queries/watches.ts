import { createQuery, createMutation, useQueryClient } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";
import type { ArtifactDetail } from "~/api/client";

// ---------------------------------------------------------------------------
// Artifact watchlist (ocidex-998g.3)
// ---------------------------------------------------------------------------

/** useWatches — GET /api/v1/users/me/watches (first keyset page). */
export function useWatches() {
    return createQuery(() => ({
        queryKey: ["watches"] as const,
        queryFn: () => unwrap(client.GET("/api/v1/users/me/watches")),
        select: (resp) => ({ ...resp, data: resp.data ?? [] }),
    }));
}

/**
 * useToggleWatch — PUT/DELETE /api/v1/users/me/watches/{artifact_id}.
 *
 * The star flips before the request lands, because a bookmark toggle that waits
 * on a round trip feels broken. The optimistic write goes into the *detail*
 * cache entry, which is where the star reads its state from; the watchlist
 * query is only invalidated on settle, since it is a different view and a
 * momentarily stale list is not misleading the way a lagging star would be.
 *
 * onError restores the exact snapshot taken in onMutate rather than
 * recomputing the flag — if two toggles race, replaying the snapshot is the
 * only way back to a state that actually existed.
 */
export function useToggleWatch() {
    const queryClient = useQueryClient();
    return createMutation(() => ({
        mutationFn: ({ artifactId, watched }: { artifactId: string; watched: boolean }) =>
            watched
                ? unwrap(
                      client.PUT("/api/v1/users/me/watches/{artifact_id}", {
                          params: { path: { artifact_id: artifactId } },
                      }),
                  )
                : unwrap(
                      client.DELETE("/api/v1/users/me/watches/{artifact_id}", {
                          params: { path: { artifact_id: artifactId } },
                      }),
                  ),
        onMutate: async ({ artifactId, watched }: { artifactId: string; watched: boolean }) => {
            const key = ["artifact", artifactId] as const;
            await queryClient.cancelQueries({ queryKey: key });
            const previous = queryClient.getQueryData<ArtifactDetail>(key);
            if (previous) {
                queryClient.setQueryData<ArtifactDetail>(key, { ...previous, watched });
            }
            return { key, previous };
        },
        onError: (
            _err: unknown,
            _vars: { artifactId: string; watched: boolean },
            ctx: { key: readonly ["artifact", string]; previous?: ArtifactDetail } | undefined,
        ) => {
            if (ctx?.previous) queryClient.setQueryData(ctx.key, ctx.previous);
        },
        onSettled: (
            _data: unknown,
            _err: unknown,
            vars: { artifactId: string; watched: boolean },
        ) => {
            void queryClient.invalidateQueries({ queryKey: ["artifact", vars.artifactId] });
            void queryClient.invalidateQueries({ queryKey: ["watches"] });
        },
    }));
}
