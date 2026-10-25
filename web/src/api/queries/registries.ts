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
export function useRecentDrift(params?: Accessor<{ limit?: number; cursor?: string }>) {
    return createQuery(() => {
        const p = params?.() ?? {};
        return {
            queryKey: ["registries", "drift-feed", p.limit, p.cursor] as const,
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
            /** Namespace to create it in, created on first use; omit for one of its own. */
            namespace?: string;
            type: "zot" | "harbor" | "docker" | "generic" | "ghcr";
            url: string;
            insecure: boolean;
            authUsername?: string;
            authToken?: string;
            repositories?: string[];
            repositoryPatterns?: string[];
            tagPatterns?: string[];
            scanMode?: "webhook" | "poll" | "both";
            pollIntervalMinutes?: number;
            visibility: "public" | "private";
            includeUntagged?: boolean;
            verificationMode?: "none" | "public_key" | "keyless";
            trustPublicKey?: string;
            trustIdentity?: string;
            trustIssuer?: string;
            tagLimit?: number;
            tagOrder?: "auto" | "semver" | "created" | "lexical";
            maxTagAgeDays?: number;
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
            authUsername?: string;
            authToken?: string;
            enabled: boolean;
            repositories?: string[];
            repositoryPatterns?: string[];
            tagPatterns?: string[];
            scanMode?: "webhook" | "poll" | "both";
            pollIntervalMinutes?: number;
            visibility?: "public" | "private";
            includeUntagged?: boolean;
            verificationMode?: "none" | "public_key" | "keyless";
            trustPublicKey?: string;
            trustIdentity?: string;
            trustIssuer?: string;
            tagLimit?: number;
            tagOrder?: "auto" | "semver" | "created" | "lexical";
            maxTagAgeDays?: number;
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
        mutationFn: ({ url, insecure, authUsername, authToken }: { url: string; insecure: boolean; authUsername?: string; authToken?: string }) =>
            unwrap(client.POST("/api/v1/registries/test-connection", { body: { url, insecure, authUsername, authToken } })),
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
            unwrap(client.POST("/api/v1/registries/{id}/webhook-secret", {
                params: { path: { id } },
            })),
    }));
}

export interface RegistryPreviewBody {
    type: "zot" | "harbor" | "docker" | "generic" | "ghcr";
    url: string;
    insecure: boolean;
    authUsername?: string;
    authToken?: string;
    repositories?: string[];
    repositoryPatterns?: string[];
    tagPatterns?: string[];
    includeUntagged?: boolean;
    tagLimit?: number;
    tagOrder?: "auto" | "semver" | "created" | "lexical";
    maxTagAgeDays?: number;
}

/**
 * What an unsaved registry config would scan (ADR-0053). It dials the registry,
 * so callers debounce `body` and pass undefined until there is something to ask.
 */
export function usePreviewRegistryConfig(body: Accessor<RegistryPreviewBody | undefined>) {
    return createQuery(() => {
        const b = body();
        return {
            queryKey: ["registries", "preview", b] as const,
            // enabled gates on b, so the fallback body is never sent.
            queryFn: () => unwrap(client.POST("/api/v1/registries/preview", { body: b ?? { type: "generic", url: "", insecure: false } })),
            enabled: b !== undefined,
            retry: false,
            staleTime: 60_000,
        };
    });
}

/** What a saved registry's next walk would scan, with its stored credentials. */
export function useRegistryPreview(id: Accessor<string | undefined>) {
    return createQuery(() => {
        const regID = id();
        return {
            queryKey: ["registries", "preview", "saved", regID] as const,
            queryFn: () => unwrap(client.GET("/api/v1/registries/{id}/preview", { params: { path: { id: regID ?? "" } } })),
            enabled: regID !== undefined,
            retry: false,
            staleTime: 60_000,
        };
    });
}
