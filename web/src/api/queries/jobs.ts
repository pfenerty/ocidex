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

export function useRetryAllFailedScanJobs() {
    const qc = useQueryClient();
    return createMutation(() => ({
        mutationFn: () => unwrap(client.POST("/api/v1/admin/jobs/retry-failed", {})),
        onSuccess: () => qc.invalidateQueries({ queryKey: ["jobs"] }),
    }));
}

export function useListEnrichmentJobs(params?: Accessor<{
    state?: "queued" | "running" | "succeeded" | "failed";
    enricher_name?: "user" | "oci-metadata" | "provenance";
    limit?: number;
    offset?: number;
}>) {
    return createQuery(() => {
        const p = params?.() ?? {};
        return {
            queryKey: ["enrichment-jobs", p.state, p.enricher_name, p.limit, p.offset] as const,
            queryFn: () => unwrap(client.GET("/api/v1/enrichment-jobs", { params: { query: p } })),
            refetchInterval: 2500,
        };
    });
}

export function useEnrichmentJobsSummary() {
    return createQuery(() => ({
        queryKey: ["enrichment-jobs", "summary"] as const,
        queryFn: () => unwrap(client.GET("/api/v1/enrichment-jobs/summary", {})),
        refetchInterval: 2500,
    }));
}

export function useRetryEnrichmentJob() {
    const qc = useQueryClient();
    return createMutation(() => ({
        mutationFn: (id: string) =>
            unwrap(client.POST("/api/v1/admin/enrichment-jobs/{id}/retry", { params: { path: { id } } })),
        onSuccess: () => qc.invalidateQueries({ queryKey: ["enrichment-jobs"] }),
    }));
}

export function useRetryAllFailedEnrichmentJobs() {
    const qc = useQueryClient();
    return createMutation(() => ({
        mutationFn: (enricher_name?: "user" | "oci-metadata" | "provenance") =>
            unwrap(client.POST("/api/v1/admin/enrichment-jobs/retry-failed", {
                params: { query: enricher_name ? { enricher_name } : {} },
            })),
        onSuccess: () => qc.invalidateQueries({ queryKey: ["enrichment-jobs"] }),
    }));
}
