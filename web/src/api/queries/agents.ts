import { createQuery, createMutation, useQueryClient } from "@tanstack/solid-query";
import type { Accessor } from "solid-js";
import { client, unwrap } from "~/api/client";
import type { components } from "~/types/openapi";

export type PendingAction = components["schemas"]["PendingActionView"];
export type KeyPreset = components["schemas"]["KeyPreset"];
export type KeyActivityEntry = components["schemas"]["KeyActivityEntry"];
type PendingStatus = NonNullable<PendingAction["status"]>;

/** The agent key presets and lifetime bounds (ADR-0058 A3). */
export function useKeyPresets() {
    return createQuery(() => ({
        queryKey: ["auth", "key-presets"],
        queryFn: () => unwrap(client.GET("/api/v1/auth/key-presets")),
        staleTime: Infinity,
    }));
}

export interface AgentKeyInput {
    name: string;
    preset: "analyst" | "remediation" | "coverage";
    namespaces: string[];
    agentLabel?: string;
    expiresAt?: string;
}

/** Mints an agent key. The plaintext comes back once. */
export function useCreateAgentKey() {
    const queryClient = useQueryClient();
    return createMutation(() => ({
        mutationFn: (input: AgentKeyInput) =>
            unwrap(client.POST("/api/v1/auth/keys", { body: { ...input, kind: "agent" } })),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["auth", "keys"] }),
    }));
}

/** Held agent writes the caller may see, newest first. */
export function useApprovals(status: Accessor<PendingStatus | undefined>) {
    return createQuery(() => ({
        queryKey: ["approvals", status()],
        queryFn: () => unwrap(client.GET("/api/v1/approvals", { params: { query: { status: status() } } })),
        select: (resp) => resp.data ?? [],
        refetchInterval: 15_000,
    }));
}

export function useApproval(id: Accessor<string>) {
    return createQuery(() => ({
        queryKey: ["approvals", "one", id()],
        queryFn: () => unwrap(client.GET("/api/v1/approvals/{id}", { params: { path: { id: id() } } })),
        enabled: id() !== "",
    }));
}

/** Approves (and so runs) or denies a held action. */
export function useDecideApproval() {
    const queryClient = useQueryClient();
    return createMutation(() => ({
        mutationFn: ({ id, approve }: { id: string; approve: boolean }) =>
            approve
                ? unwrap(client.POST("/api/v1/approvals/{id}/approve", { params: { path: { id } } }))
                : unwrap(client.POST("/api/v1/approvals/{id}/deny", { params: { path: { id } } })),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["approvals"] }),
    }));
}

/** What one of the caller's agent keys did. */
export function useKeyActivity(id: Accessor<string>, enabled: Accessor<boolean>) {
    return createQuery(() => ({
        queryKey: ["auth", "keys", id(), "activity"],
        queryFn: () =>
            unwrap(client.GET("/api/v1/auth/keys/{id}/activity", { params: { path: { id: id() }, query: { limit: 50 } } })),
        select: (resp) => resp.data ?? [],
        enabled: enabled(),
    }));
}
