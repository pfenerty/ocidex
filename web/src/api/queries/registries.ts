import type { Accessor } from "solid-js";
import { createQuery, createMutation, useQueryClient } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";

export function useListRegistries() {
    return createQuery(() => ({
        queryKey: ["registries"],
        queryFn: () => unwrap(client.GET("/api/v1/registries")),
    }));
}

/** Admin-only: per-registry signing-status counts. */
export function useRegistryTrustSummary() {
    return createQuery(() => ({
        queryKey: ["registries", "trust-summary"] as const,
        queryFn: () => unwrap(client.GET("/api/v1/registries/trust-summary", {})),
    }));
}

/** Admin-only: most recent provenance drift events across all registries. */
export function useRecentDrift(params?: Accessor<{ limit?: number; offset?: number }>) {
    return createQuery(() => {
        const p = params?.() ?? {};
        return {
            queryKey: ["registries", "drift-feed", p.limit, p.offset] as const,
            queryFn: () =>
                unwrap(client.GET("/api/v1/registries/drift-feed", { params: { query: p } })),
        };
    });
}

export function useCreateRegistry() {
    const queryClient = useQueryClient();
    return createMutation(() => ({
        mutationFn: (body: {
            name: string;
            type: "zot" | "harbor" | "docker" | "generic" | "ghcr";
            url: string;
            insecure: boolean;
            auth_username?: string;
            auth_token?: string;
            repositories?: string[];
            repository_patterns?: string[];
            tag_patterns?: string[];
            scan_mode?: "webhook" | "poll" | "both";
            poll_interval_minutes?: number;
            visibility: "public" | "private";
            include_untagged?: boolean;
            verification_mode?: "none" | "public_key" | "keyless";
            trust_public_key?: string;
            trust_identity?: string;
            trust_issuer?: string;
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
            type: "zot" | "harbor" | "docker" | "generic" | "ghcr";
            url: string;
            insecure: boolean;
            auth_username?: string;
            auth_token?: string;
            enabled: boolean;
            repositories?: string[];
            repository_patterns?: string[];
            tag_patterns?: string[];
            scan_mode?: "webhook" | "poll" | "both";
            poll_interval_minutes?: number;
            visibility?: "public" | "private";
            include_untagged?: boolean;
            verification_mode?: "none" | "public_key" | "keyless";
            trust_public_key?: string;
            trust_identity?: string;
            trust_issuer?: string;
        }) =>
            unwrap(
                client.PATCH("/api/v1/registries/{id}", {
                    params: { path: { id } },
                    body,
                })
            ),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["registries"] }),
    }));
}

export function useTestRegistryConnection() {
    return createMutation(() => ({
        mutationFn: ({ url, insecure, auth_username, auth_token }: { url: string; insecure: boolean; auth_username?: string; auth_token?: string }) =>
            unwrap(client.POST("/api/v1/registries/test-connection", { body: { url, insecure, auth_username, auth_token } })),
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
        mutationFn: ({ id, force }: { id: string; force?: boolean }) =>
            unwrap(client.POST("/api/v1/registries/{id}/scan", {
                params: { path: { id }, query: force === true ? { force: true } : {} },
            })),
    }));
}

export function useRegenerateWebhookSecret() {
    return createMutation(() => ({
        mutationFn: (id: string) =>
            fetch(`/api/v1/registries/${id}/webhook-secret`, {
                method: "POST",
                credentials: "include",
            }).then(async (res) => {
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                return res.json() as Promise<{ webhook_secret: string }>;
            }),
    }));
}
