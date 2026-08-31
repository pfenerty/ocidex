import { createQuery, createMutation, useQueryClient } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";
import type { Capability } from "~/api/client";

export function useListAPIKeys() {
    return createQuery(() => ({
        queryKey: ["auth", "keys"],
        queryFn: () => unwrap(client.GET("/api/v1/auth/keys")),
    }));
}

export function useCreateAPIKey() {
    const queryClient = useQueryClient();
    return createMutation(() => ({
        mutationFn: ({ name, capabilities }: { name: string; capabilities: Capability[] }) =>
            unwrap(client.POST("/api/v1/auth/keys", { body: { name, capabilities } })),
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

/**
 * The issuers this deployment is configured with.
 *
 * Public, and deliberately so: the login page has to render its buttons before
 * anyone is signed in.
 */
export function useAuthProviders() {
    return createQuery(() => ({
        queryKey: ["auth", "providers"],
        queryFn: () => unwrap(client.GET("/api/v1/auth/providers")),
        // Issuers change when the deployment is reconfigured, not while someone
        // is looking at the login page.
        staleTime: 5 * 60_000,
    }));
}

/** The caller's own linked identities. */
export function useMyIdentities() {
    return createQuery(() => ({
        queryKey: ["auth", "identities"],
        queryFn: () => unwrap(client.GET("/api/v1/auth/identities")),
    }));
}

/**
 * Begins a link round trip and returns where to send the browser.
 *
 * The navigation is the caller's job: this leaves the page, so it cannot be a
 * redirect the fetch follows.
 */
export function useStartIdentityLink() {
    return createMutation(() => ({
        mutationFn: (provider: string) =>
            unwrap(client.POST("/api/v1/auth/identities", { body: { provider } })),
    }));
}

export function useUnlinkIdentity() {
    const queryClient = useQueryClient();
    return createMutation(() => ({
        mutationFn: (id: string) =>
            unwrap(client.DELETE("/api/v1/auth/identities/{id}", { params: { path: { id } } })),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["auth", "identities"] }),
    }));
}
