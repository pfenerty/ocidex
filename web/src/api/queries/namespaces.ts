import type { Accessor } from "solid-js";
import { createQuery, createMutation, useQueryClient } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";

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
