import type { Accessor } from "solid-js";
import { createMutation, createQuery, useQueryClient } from "@tanstack/solid-query";
import { client, unwrap } from "~/api/client";

export function useListScanJobs(params?: Accessor<{
    state?: "queued" | "running" | "succeeded" | "failed";
    limit?: number;
    offset?: number;
}>) {
    return createQuery(() => {
        const p = params?.() ?? {};
        return {
            queryKey: ["jobs", p.state, p.limit, p.offset] as const,
            queryFn: () => unwrap(client.GET("/api/v1/jobs", { params: { query: p } })),
            refetchInterval: 2500,
        };
    });
}

export function useGetScanJob(id: Accessor<string>) {
    return createQuery(() => ({
        queryKey: ["jobs", id()] as const,
        queryFn: () => unwrap(client.GET("/api/v1/jobs/{id}", { params: { path: { id: id() } } })),
        refetchInterval: 2500,
    }));
}

export function useRetryScanJob() {
    const qc = useQueryClient();
    return createMutation(() => ({
        mutationFn: (id: string) =>
            unwrap(client.POST("/api/v1/admin/jobs/{id}/retry", { params: { path: { id } } })),
        onSuccess: () => qc.invalidateQueries({ queryKey: ["jobs"] }),
    }));
}
