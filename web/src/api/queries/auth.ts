import { createQuery, createMutation, useQueryClient } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";

export function useListAPIKeys() {
    return createQuery(() => ({
        queryKey: ["auth", "keys"],
        queryFn: () => unwrap(client.GET("/api/v1/auth/keys")),
    }));
}

export function useCreateAPIKey() {
    const queryClient = useQueryClient();
    return createMutation(() => ({
        mutationFn: (name: string) =>
            unwrap(client.POST("/api/v1/auth/keys", { body: { name } })),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["auth", "keys"] }),
    }));
}

export function useDeleteAPIKey() {
    const queryClient = useQueryClient();
    return createMutation(() => ({
        mutationFn: (id: string) =>
            unwrap(client.DELETE("/api/v1/auth/keys/{id}", { params: { path: { id } } })),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["auth", "keys"] }),
    }));
}

export function useListUsers() {
    return createQuery(() => ({
        queryKey: ["users"],
        queryFn: () => unwrap(client.GET("/api/v1/users")),
    }));
}

export function useUpdateUserRole() {
    const queryClient = useQueryClient();
    return createMutation(() => ({
        mutationFn: ({ id, role }: { id: string; role: "admin" | "member" | "viewer" }) =>
            unwrap(client.PATCH("/api/v1/users/{id}/role", { params: { path: { id } }, body: { role } })),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["users"] }),
    }));
}

export function useGetSystemStatus() {
    return createQuery(() => ({
        queryKey: ["admin", "status"],
        queryFn: () => unwrap(client.GET("/api/v1/admin/status")),
    }));
}
