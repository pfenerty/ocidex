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
 * later would overwrite the URL anyway. Fixed-URL types have no webhook, so the
 * scan mode is moved with it rather than left on a value the form would reject.
 * Everything stays editable; this only saves typing.
 */
export function prefillForHost(host: string): Partial<RegistryFormState> {
    const match = (Object.keys(TYPE_CAPS) as RegType[]).find(
        (t) => TYPE_CAPS[t].fixedUrl === host,
    );
    const type: RegType = match ?? "generic";
    return {
        name: host,
        type,
        url: TYPE_CAPS[type].fixedUrl ?? host,
        scanMode: TYPE_CAPS[type].webhook ? "webhook" : "poll",
    };
}

export function toPatternArray(s: string): string[] {
    return s.split("\n").map(p => p.trim()).filter(p => p !== "");
}

/** hasWebhook is true when a registry both supports and uses webhook ingest. */
export const hasWebhook = (reg: { scan_mode?: string; type: string }): boolean =>
    reg.scan_mode !== "poll" && TYPE_CAPS[reg.type as RegType].webhook;
