import createClient from "openapi-fetch";
import type { paths, components } from "~/types/openapi";

// Base URL of the API server. Set VITE_API_URL at build time; defaults to
// same-origin (e.g. when the Go binary serves the frontend statically).
export const API_BASE_URL: string = import.meta.env.VITE_API_URL ?? "";

/**
 * Default page size for paginated list endpoints. Kept in sync with the backend
 * default (internal/api/types.go PaginationParams/CursorParams). Use this for
 * every default-page-size list rather than re-hardcoding a limit per page.
 */
export const DEFAULT_PAGE_SIZE = 20;

// credentials: "include" so the session cookie also flows when VITE_API_URL
// points at a different origin than the one serving the SPA — the supported
// deployment shape when there is no Gateway/Ingress giving a same-origin /api.
// Requires the API's CORS_ALLOWED_ORIGINS to list the frontend origin.
export const client = createClient<paths>({
    baseUrl: API_BASE_URL,
    credentials: "include",
});

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
 *
 * It deliberately does not redirect on 401. It used to send the browser to
 * /login on any 401, which meant a single auth-scoped widget could destroy an
 * otherwise-public page: /vulnerabilities/{id} bounced signed-out visitors even
 * though the CVE endpoint itself answered 200, because one sibling request for
 * cluster workloads was authenticated.
 *
 * Redirecting is a routing decision and lives in one place: Layout's
 * `authedPaths` effect, which navigates when the auth resource resolves to no
 * user on a path whose every request is authenticated. Anywhere else, a 401 is
 * data — the caller decides whether to hide a section, show an error, or fall
 * back to an empty result. Use `isUnauthorized` to detect it.
 */
export async function unwrap<T>(
    promise: Promise<{ data?: T; error?: unknown; response: Response }>,
): Promise<T> {
    const { data, error, response } = await promise;
    if (error !== undefined && error !== null) {
        throw new APIClientError(response.status, error);
    }
    return data as T;
}

/**
 * isUnauthorized reports whether a thrown value is a 401 from the API.
 *
 * Callers that render an auth-scoped section inside an otherwise-public page
 * use this to degrade that section rather than fail the page.
 */
export function isUnauthorized(err: unknown): boolean {
    return err instanceof APIClientError && err.status === 401;
}

// Re-export generated component schemas for convenience so pages can import
// types from "~/api/client" without reaching into the openapi types directly.
export type { paths, components };
export type ArtifactSummary = components["schemas"]["ArtifactSummary"];
export type ArtifactDetail = components["schemas"]["ArtifactDetail"];
export type ArtifactVersionSummary = components["schemas"]["ArtifactVersionSummary"];
export type ArtifactRelation = components["schemas"]["ArtifactRelation"];
export type SBOMSummary = components["schemas"]["SBOMSummary"];
export type SBOMDetail = components["schemas"]["SBOMDetail"];
export type ProvenanceDriftSummary = components["schemas"]["ProvenanceDriftSummary"];
export type RecentDriftEntry = components["schemas"]["RecentDriftEntry"];
export type RegistryTrustCount = components["schemas"]["RegistryTrustCount"];
export type ComponentSummary = components["schemas"]["ComponentSummary"];
export type ComponentDetail = components["schemas"]["ComponentDetail"];
export type VulnSummary = components["schemas"]["VulnSummary"];
export type SBOMVulnEntry = components["schemas"]["SBOMVulnEntry"];
export type SBOMVulnPackage = components["schemas"]["SBOMVulnPackage"];
export type ArtifactVulnEntry = components["schemas"]["ArtifactVulnEntry"];
export type ArtifactVulnVersion = components["schemas"]["ArtifactVulnVersion"];
export type Cluster = components["schemas"]["ClusterResponse"];
export type ClusterWorkload = components["schemas"]["ClusterWorkloadResponse"];
export type ClusterImage = components["schemas"]["ClusterImageResponse"];
export type WorkloadCoverage = components["schemas"]["WorkloadCoverageResponse"];
export type WorkloadMatchState = ClusterWorkload["match_state"];
export type RunningVuln = components["schemas"]["RunningVulnResponse"];
export type UnknownImage = components["schemas"]["UnknownImageResponse"];
/** Why an unknown image can or cannot be ingested; each value has its own remedy. */
export type IngestReason = UnknownImage["reason"];
/** Per-reason counts from one ingest run (ADR-044 auto-ingest amendment). */
export type IngestResult = components["schemas"]["IngestUnknownOutputBody"];
export type RunningWorkload = components["schemas"]["RunningWorkloadResponse"];
export type NamespaceFacet = components["schemas"]["NamespaceFacetResponse"];
export type DistinctComponentSummary =
    components["schemas"]["DistinctComponentSummary"];
export type ComponentVersionEntry =
    components["schemas"]["ComponentVersionEntry"];
export type LicenseCount = components["schemas"]["LicenseCount"];
export type LicenseSummary = components["schemas"]["LicenseSummary"];
export type DependencyGraph = components["schemas"]["DependencyGraph"];
export type DependencyEdge = components["schemas"]["DependencyEdge"];
export type DiffTree = components["schemas"]["DiffTree"];
export type Changelog = components["schemas"]["Changelog"];
export type ChangelogEntry = components["schemas"]["ChangelogEntry"];
export type SBOMRef = components["schemas"]["SBOMRef"];
export type ChangeSummary = components["schemas"]["ChangeSummary"];
export type ComponentDiff = components["schemas"]["ComponentDiff"];
export type HashEntry = components["schemas"]["HashEntry"];
export type ExternalRefEntry = components["schemas"]["ExternalRefEntry"];
export type IngestResponse = components["schemas"]["IngestSBOMOutputBody"];
export type PaginationMeta = components["schemas"]["PaginationMeta"];
export type ScanJob = components["schemas"]["ScanJobResponse"];
export type EnrichmentJob = components["schemas"]["EnrichmentJobResponse"];
export type Registry = components["schemas"]["RegistryResponse"];
export type Source = components["schemas"]["SourceResponse"];
export type Namespace = components["schemas"]["NamespaceResponse"];
export type NamespaceMember = components["schemas"]["NamespaceMemberResponse"];
/**
 * The closed role set (ADR-046). It comes from the generated schema rather than
 * a hand-written union so that adding a role in Go is a compile error here
 * until the UI decides what to do with it.
 */
export type NamespaceRole = NamespaceMember["role"];
export type APIKey = components["schemas"]["KeyMetaResponse"];
/**
 * The closed capability set (ADR-046), taken from the create-key request body
 * so that adding a capability in Go is a compile error here until the UI lists
 * it. The key-listing response is plain strings — a key minted by a newer build
 * can name a capability this one has never heard of.
 */
export type Capability = NonNullable<
    components["schemas"]["CreateAPIKeyInputBody"]["capabilities"]
>[number];
export type UserAccount = components["schemas"]["UserResponse"];
export type ErrorModel = components["schemas"]["ErrorModel"];
export type DashboardStats = components["schemas"]["DashboardStatsOutputBody"];
export type CategoryCountEntry = components["schemas"]["CategoryCountEntry"];
export type DailyCountEntry = components["schemas"]["DailyCountEntry"];
export type PackageSummaryEntry = components["schemas"]["PackageSummaryEntry"];
export type TopVulnEntry = components["schemas"]["TopVulnEntry"];

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

export interface Provenance {
    signaturePresent: boolean;
    attestationPresent: boolean;
    verified?: boolean;
    signerFingerprint?: string;
    predicateType?: string;
    builderId?: string;
    sourceUri?: string;
    sourceCommit?: string;
    buildStartedOn?: string;
    subjects?: string[];
    rekorUuid?: string;
    rekorLogIndex?: number;
    signerIdentity?: string;
    signerIssuer?: string;
    artifactMissing?: boolean;
    /**
     * Why verification did not succeed — the cosign rejection reasons when
     * `verified` is false, or why verification could not run at all when
     * `verified` is undefined. Advisory: it does not affect signingStatus.
     */
    verificationError?: string;
}

/**
 * Client-side type for git commit metadata stored in SBOM enrichments under
 * the "git" key. Not part of the OpenAPI spec (enrichments is Record<string, unknown>).
 */
export interface GitCommitMetadata {
    resolved: boolean;
    reason?: string;
    host?: string;
    owner?: string;
    repo?: string;
    commitSha?: string;
    commitUrl?: string;
    authorName?: string;
    authorEmail?: string;
    authoredAt?: string;
    committerName?: string;
    committerEmail?: string;
    committedAt?: string;
    messageSubject?: string;
    parents?: string[];
}
