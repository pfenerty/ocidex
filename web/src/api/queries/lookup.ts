import { createQuery } from "@tanstack/solid-query";
import { client, unwrap, APIClientError } from "~/api/client";
import type { Accessor } from "solid-js";
import type { components } from "~/api/client";

export type LookupCandidate = components["schemas"]["LookupCandidate"];
type LookupConflictError = components["schemas"]["LookupConflictError"];

/** ADR-042 R4 qualifier ladder for GET /api/v1/artifacts/lookup. */
export interface UseArtifactLookupParams {
    name: string;
    type?: string;
    group?: string;
}

/** ADR-042 R4 qualifier ladder for GET /api/v1/sboms/lookup. Supply either
 *  digest on its own, or artifact + version narrowed with arch then flavor. */
export interface UseSBOMLookupParams {
    artifact?: string;
    version?: string;
    arch?: string;
    flavor?: string;
    digest?: string;
}

/**
 * Resolve an artifact name (plus optional qualifiers) to its canonical record.
 * A 409 is a real answer, not a transient failure, so retry is off — the caller
 * renders the candidates from `conflictCandidates(query.error)`.
 */
export function useArtifactLookup(params: Accessor<UseArtifactLookupParams>) {
    return createQuery(() => {
        const p = params();
        return {
            queryKey: ["artifact-lookup", p.name, p.type, p.group] as const,
            queryFn: () =>
                unwrap(
                    client.GET("/api/v1/artifacts/lookup", {
                        params: {
                            query: {
                                name: p.name,
                                type: p.type !== "" ? p.type : undefined,
                                group: p.group !== "" ? p.group : undefined,
                            },
                        },
                    }),
                ),
            enabled: p.name !== "",
            retry: false,
        };
    });
}

/** Resolve an SBOM name+version (or digest) to its canonical record. */
export function useSBOMLookup(params: Accessor<UseSBOMLookupParams>) {
    return createQuery(() => {
        const p = params();
        return {
            queryKey: [
                "sbom-lookup",
                p.artifact,
                p.version,
                p.arch,
                p.flavor,
                p.digest,
            ] as const,
            queryFn: () =>
                unwrap(
                    client.GET("/api/v1/sboms/lookup", {
                        params: {
                            query: {
                                artifact: p.artifact !== "" ? p.artifact : undefined,
                                version: p.version !== "" ? p.version : undefined,
                                arch: p.arch !== "" ? p.arch : undefined,
                                flavor: p.flavor !== "" ? p.flavor : undefined,
                                digest: p.digest !== "" ? p.digest : undefined,
                            },
                        },
                    }),
                ),
            enabled:
                (p.digest ?? "") !== "" ||
                ((p.artifact ?? "") !== "" && (p.version ?? "") !== ""),
            retry: false,
        };
    });
}

/**
 * Candidates from an ambiguous resolver response, or null for any other error.
 * The 409 body is the only one carrying them, so this doubles as the test for
 * "was this an ambiguity rather than a failure".
 */
export function conflictCandidates(error: unknown): LookupCandidate[] | null {
    if (!(error instanceof APIClientError) || error.status !== 409) return null;
    const body = error.body as LookupConflictError | undefined;
    return body?.candidates ?? null;
}

/** True when the resolver found nothing visible matching the query. */
export function isNotFound(error: unknown): boolean {
    return error instanceof APIClientError && error.status === 404;
}
