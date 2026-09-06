export type RegType = "zot" | "harbor" | "docker" | "generic" | "ghcr";

/**
 * TYPE_CAPS is what each registry type can actually do. The form reads it
 * rather than branching on the type name in a dozen places: Docker Hub and
 * GHCR have a fixed URL and no webhook support, so choosing them has to
 * simultaneously lock the URL, force poll mode, and clear include-untagged.
 */
export const TYPE_CAPS: Record<RegType, { label: string; fixedUrl: string | null; webhook: boolean; untagged: boolean }> = {
    docker:  { label: "Docker Hub",                        fixedUrl: "registry-1.docker.io", webhook: false, untagged: false },
    ghcr:    { label: "GitHub Container Registry (GHCR)", fixedUrl: "ghcr.io",               webhook: false, untagged: true  },
    zot:     { label: "Zot",                               fixedUrl: null,                    webhook: true,  untagged: true  },
    harbor:  { label: "Harbor",                            fixedUrl: null,                    webhook: true,  untagged: true  },
    generic: { label: "Generic OCI Registry",              fixedUrl: null,                    webhook: true,  untagged: false },
};

export const regTypeLabel = (t: string): string => (t in TYPE_CAPS ? TYPE_CAPS[t as RegType].label : t);

export type ScanMode = "webhook" | "poll" | "both";
export type Visibility = "public" | "private";
export type VerificationMode = "none" | "public_key" | "keyless";

export interface RegistryFormState {
    name: string;
    /**
     * Namespace to create the registry in, created on first use. Empty means
     * "give it a namespace of its own named after it" — the API's documented
     * default, and the only shape this form could express before ADR-039's
     * tenancy boundary had a field here.
     */
    namespace: string;
    type: RegType;
    url: string;
    insecure: boolean;
    authUsername: string;
    authToken: string;
    repositories: string;       // newline-separated explicit repos
    repositoryPatterns: string; // newline-separated
    tagPatterns: string;        // newline-separated
    scanMode: ScanMode;
    pollIntervalMinutes: number;
    visibility: Visibility;
    includeUntagged: boolean;
    verificationMode: VerificationMode;
    trustPublicKey: string;
    trustIdentity: string;
    trustIssuer: string;
}

export const emptyForm = (): RegistryFormState => ({
    name: "",
    namespace: "",
    type: "generic",
    url: "",
    insecure: false,
    authUsername: "",
    authToken: "",
    repositories: "",
    repositoryPatterns: "",
    tagPatterns: "",
    scanMode: "webhook",
    pollIntervalMinutes: 60,
    visibility: "public",
    includeUntagged: false,
    verificationMode: "none",
    trustPublicKey: "",
    trustIdentity: "",
    trustIssuer: "",
});

/**
 * prefillForHost seeds the add-registry form from a registry host observed
 * somewhere else in the app — the cluster Gaps tab knows an image came from
 * `ghcr.io` and nothing is configured for it.
 *
 * A host that matches a type's fixed URL selects that type, because choosing it
 * later would overwrite the URL anyway. Everything stays editable; this only
 * saves typing.
 *
 * Scan mode is always `poll`, unlike the empty form's `webhook`. A host reached
 * this function because it was *observed* — an image running in a cluster named
 * it — which says nothing about anyone being able to push a webhook to us from
 * it. Leaving the form on webhook would let a reader close the dialog on a
 * registry that never scans, and the gap that sent them here would still be
 * there tomorrow with no indication why.
 *
 * `namespace` is the tenancy boundary the registry has to land in to be of any
 * use to the caller. Registry resolution is namespace-local by design
 * (`clusterService.UnknownImages`), so a registry created from a cluster's gap
 * into a namespace of its own — the API's default — closes nothing: the button
 * would promise a fix and deliver a registry the cluster cannot see.
 *
 * `repos` are the repositories actually seen at that host — on the Gaps tab,
 * exactly the ones behind the gap. They go into Repositories rather than being
 * offered as a hint because that field is *required* for ghcr.io and quay.io,
 * which do not support catalog discovery, and because a list drawn from the gap
 * is the one list guaranteed to close it. It is a visible, editable textarea:
 * a reader who wants catalog discovery on a Zot or Harbor clears it.
 */
export function prefillForHost(
    host: string,
    repos?: string[],
    namespace?: string,
): Partial<RegistryFormState> {
    const match = (Object.keys(TYPE_CAPS) as RegType[]).find(
        (t) => TYPE_CAPS[t].fixedUrl === host,
    );
    const type: RegType = match ?? "generic";
    return {
        name: host,
        type,
        url: TYPE_CAPS[type].fixedUrl ?? host,
        scanMode: "poll",
        ...(namespace === undefined || namespace === "" ? {} : { namespace }),
        ...(repos === undefined || repos.length === 0 ? {} : { repositories: repos.join("\n") }),
    };
}

export function toPatternArray(s: string): string[] {
    return s.split("\n").map(p => p.trim()).filter(p => p !== "");
}

/** hasWebhook is true when a registry both supports and uses webhook ingest. */
export const hasWebhook = (reg: { scan_mode?: string; type: string }): boolean =>
    reg.scan_mode !== "poll" && TYPE_CAPS[reg.type as RegType].webhook;
