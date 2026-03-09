import createClient from "openapi-fetch";
import type { paths, components } from "~/types/openapi";

// Base URL of the API server. Set VITE_API_URL at build time; defaults to
// same-origin (e.g. when the Go binary serves the frontend statically).
export const API_BASE_URL: string = import.meta.env.VITE_API_URL ?? "";

export const client = createClient<paths>({ baseUrl: API_BASE_URL });

/**
 * APIClientError wraps a non-2xx response from the API.
 * The body contains the RFC 7807 problem details object.
 */
export class APIClientError extends Error {
    constructor(
        public status: number,
        public body: unknown,
    ) {
        super(`API error ${status}`);
        this.name = "APIClientError";
    }
}

/**
 * Unwrap an openapi-fetch result: return data on success, throw on error.
 * Designed for use inside solid-query `queryFn` callbacks.
 */
export async function unwrap<T>(
    promise: Promise<{ data?: T; error?: unknown; response: Response }>,
): Promise<T> {
    const { data, error, response } = await promise;
    if (error !== undefined && error !== null) {
        if (response.status === 401) {
            window.location.href = "/login";
        }
        throw new APIClientError(response.status, error);
    }
    return data as T;
}

// Re-export generated component schemas for convenience so pages can import
// types from "~/api/client" without reaching into the openapi types directly.
export type { paths, components };
export type ArtifactSummary = components["schemas"]["ArtifactSummary"];
export type ArtifactDetail = components["schemas"]["ArtifactDetail"];
export type SBOMSummary = components["schemas"]["SBOMSummary"];
export type SBOMDetail = components["schemas"]["SBOMDetail"];
export type ComponentSummary = components["schemas"]["ComponentSummary"];
export type ComponentDetail = components["schemas"]["ComponentDetail"];
export type DistinctComponentSummary =
    components["schemas"]["DistinctComponentSummary"];
export type ComponentVersionEntry =
    components["schemas"]["ComponentVersionEntry"];
export type LicenseCount = components["schemas"]["LicenseCount"];
export type LicenseSummary = components["schemas"]["LicenseSummary"];
export type DependencyGraph = components["schemas"]["DependencyGraph"];
export type DependencyEdge = components["schemas"]["DependencyEdge"];
export type Changelog = components["schemas"]["Changelog"];
export type ChangelogEntry = components["schemas"]["ChangelogEntry"];
export type SBOMRef = components["schemas"]["SBOMRef"];
export type ChangeSummary = components["schemas"]["ChangeSummary"];
export type ComponentDiff = components["schemas"]["ComponentDiff"];
export type HashEntry = components["schemas"]["HashEntry"];
export type ExternalRefEntry = components["schemas"]["ExternalRefEntry"];
export type IngestResponse = components["schemas"]["IngestSBOMOutputBody"];
export type PaginationMeta = components["schemas"]["PaginationMeta"];
export type ErrorModel = components["schemas"]["ErrorModel"];
export type DashboardStats = components["schemas"]["DashboardStatsOutputBody"];
export type CategoryCountEntry = components["schemas"]["CategoryCountEntry"];
export type DailyCountEntry = components["schemas"]["DailyCountEntry"];
export type PackageSummaryEntry = components["schemas"]["PackageSummaryEntry"];

/**
 * Client-side type for OCI image metadata stored in SBOM enrichments.
 * This is not part of the OpenAPI spec (enrichments is Record<string, unknown>).
 */
export interface OCIMetadata {
    architecture?: string;
    os?: string;
    created?: string;
    labels?: Record<string, string>;
    manifestAnnotations?: Record<string, string>;
    indexAnnotations?: Record<string, string>;
    imageVersion?: string;
    sourceUrl?: string;
    revision?: string;
    authors?: string;
    description?: string;
    baseName?: string;
    url?: string;
    documentation?: string;
    vendor?: string;
    licenses?: string;
    title?: string;
    baseDigest?: string;
}
