import type { Accessor } from "solid-js";
import { createQuery, createMutation, useQueryClient } from "@tanstack/solid-query";
import { client, unwrap, type NamespaceRole } from "~/api/client";

/**
 * Namespaces owned by the caller plus every public one (ADR-039). The namespace
 * is the entity that owns artifacts and governs visibility — sources and
 * registries inherit their answer from it — so this list is the root of every
 * ownership affordance in the UI.
 */
export function useListNamespaces() {
    return createQuery(() => ({
        queryKey: ["namespaces"] as const,
        queryFn: () => unwrap(client.GET("/api/v1/namespaces")),
        select: (resp) => ({ ...resp, data: resp.data ?? [] }),
    }));
}

export function useNamespace(id: Accessor<string | undefined>, opts?: { enabled?: Accessor<boolean> }) {
    return createQuery(() => ({
        queryKey: ["namespaces", id()] as const,
        queryFn: () =>
            unwrap(client.GET("/api/v1/namespaces/{id}", { params: { path: { id: id() ?? "" } } })),
        enabled: (opts?.enabled?.() ?? true) && id() !== undefined,
    }));
}

export function useCreateNamespace() {
    const queryClient = useQueryClient();
    return createMutation(() => ({
        mutationFn: (body: { name: string; visibility?: "public" | "private" }) =>
            unwrap(client.POST("/api/v1/namespaces", { body })),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["namespaces"] }),
    }));
}

export function useUpdateNamespace() {
    const queryClient = useQueryClient();
    return createMutation(() => ({
        mutationFn: ({ id, ...body }: { id: string; name?: string; visibility?: "public" | "private" }) =>
            unwrap(client.PATCH("/api/v1/namespaces/{id}", { params: { path: { id } }, body })),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["namespaces"] }),
    }));
}

/**
 * Deleting a namespace removes everything ingested under it, so the sources and
 * artifact lists are invalidated alongside it rather than left showing rows that
 * no longer resolve.
 */
export function useDeleteNamespace() {
    const queryClient = useQueryClient();
    return createMutation(() => ({
        mutationFn: (id: string) =>
            unwrap(client.DELETE("/api/v1/namespaces/{id}", { params: { path: { id } } })),
        onSuccess: () => {
            void queryClient.invalidateQueries({ queryKey: ["namespaces"] });
            void queryClient.invalidateQueries({ queryKey: ["sources"] });
            void queryClient.invalidateQueries({ queryKey: ["registries"] });
            void queryClient.invalidateQueries({ queryKey: ["artifacts"] });
        },
    }));
}

/**
 * A namespace's members and their roles (ADR-046). The endpoint requires the
 * manage_member capability, which only the owner and an installation admin
 * hold, so this query is enabled only where the caller can actually use it — a
 * disabled query is what keeps a viewer's namespace row from firing a 403 on
 * every render.
 */
export function useNamespaceMembers(
    id: Accessor<string | undefined>,
    opts?: { enabled?: Accessor<boolean> },
) {
    return createQuery(() => ({
        queryKey: ["namespaces", id(), "members"] as const,
        queryFn: () =>
            unwrap(
                client.GET("/api/v1/namespaces/{id}/members", {
                    params: { path: { id: id() ?? "" } },
                }),
            ),
        enabled: (opts?.enabled?.() ?? true) && id() !== undefined,
        select: (resp) => ({ ...resp, data: resp.data ?? [] }),
    }));
}

/** Adds a member or changes an existing member's role. */
export function useSetNamespaceMember() {
    const queryClient = useQueryClient();
    return createMutation(() => ({
        mutationFn: ({ id, userID, role }: { id: string; userID: string; role: NamespaceRole }) =>
            unwrap(
                client.PUT("/api/v1/namespaces/{id}/members/{user_id}", {
                    params: { path: { id, user_id: userID } },
                    body: { role },
                }),
            ),
        onSuccess: (_data, vars) =>
            queryClient.invalidateQueries({ queryKey: ["namespaces", vars.id, "members"] }),
    }));
}

/** Removes a member. Removing the owner is refused by the API with a 409. */
export function useRemoveNamespaceMember() {
    const queryClient = useQueryClient();
    return createMutation(() => ({
        mutationFn: ({ id, userID }: { id: string; userID: string }) =>
            unwrap(
                client.DELETE("/api/v1/namespaces/{id}/members/{user_id}", {
                    params: { path: { id, user_id: userID } },
                }),
            ),
        onSuccess: (_data, vars) =>
            queryClient.invalidateQueries({ queryKey: ["namespaces", vars.id, "members"] }),
    }));
}
