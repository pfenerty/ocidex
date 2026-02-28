import { createQuery, createMutation, useQueryClient } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";

export function useListRegistries() {
    return createQuery(() => ({
        queryKey: ["registries"],
        queryFn: () => unwrap(client.GET("/api/v1/registries")),
    }));
}

export function useCreateRegistry() {
    const queryClient = useQueryClient();
    return createMutation(() => ({
        mutationFn: (body: {
            name: string;
            type: "zot" | "harbor" | "docker" | "generic";
            url: string;
            insecure: boolean;
            webhook_secret?: string;
            repository_patterns?: string[];
            tag_patterns?: string[];
        }) => unwrap(client.POST("/api/v1/registries", { body })),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["registries"] }),
    }));
}

export function useUpdateRegistry() {
    const queryClient = useQueryClient();
    return createMutation(() => ({
        mutationFn: ({
            id,
            ...body
        }: {
            id: string;
            name: string;
            type: "zot" | "harbor" | "docker" | "generic";
            url: string;
            insecure: boolean;
            webhook_secret?: string;
            enabled: boolean;
            repository_patterns?: string[];
            tag_patterns?: string[];
        }) =>
            unwrap(
                client.PUT("/api/v1/registries/{id}", {
                    params: { path: { id } },
                    body,
                })
            ),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["registries"] }),
    }));
}

export function useTestRegistryConnection() {
    return createMutation(() => ({
        mutationFn: ({ url, insecure }: { url: string; insecure: boolean }) =>
            unwrap(client.POST("/api/v1/registries/test-connection", { body: { url, insecure } })),
    }));
}

export function useDeleteRegistry() {
    const queryClient = useQueryClient();
    return createMutation(() => ({
        mutationFn: (id: string) =>
            unwrap(client.DELETE("/api/v1/registries/{id}", { params: { path: { id } } })),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["registries"] }),
    }));
}

export function useScanRegistry() {
    return createMutation(() => ({
        mutationFn: (id: string) =>
            unwrap(client.POST("/api/v1/registries/{id}/scan", { params: { path: { id } } })),
    }));
}
