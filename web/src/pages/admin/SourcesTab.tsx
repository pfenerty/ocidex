import "./SourcesTab.css";
import { For, Show, createSignal, createMemo } from "solid-js";
import { A } from "@solidjs/router";
import { copyText } from "~/utils/clipboard";
import { useToast } from "~/context/toast";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import type { Registry, Source } from "~/api/client";
import { trustBadgeClass, signingStatusLabel, trustStatus, driftReasonLabel } from "~/utils/trust";
import { formatDateTime } from "~/utils/format";
import {
    useListRegistries,
    useCreateRegistry,
    useUpdateRegistry,
    useDeleteRegistry,
    useTestRegistryConnection,
    useScanRegistry,
    useRegenerateWebhookSecret,
    useGetSystemStatus,
    useListScanJobs,
    useRegistryTrustSummary,
    useRecentDrift,
    useListSources,
} from "~/api/queries";

type RegType = "zot" | "harbor" | "docker" | "generic" | "ghcr";

const TYPE_CAPS: Record<RegType, { label: string; fixedUrl: string | null; webhook: boolean; untagged: boolean }> = {
    docker:  { label: "Docker Hub",                        fixedUrl: "registry-1.docker.io", webhook: false, untagged: false },
    ghcr:    { label: "GitHub Container Registry (GHCR)", fixedUrl: "ghcr.io",               webhook: false, untagged: true  },
    zot:     { label: "Zot",                               fixedUrl: null,                    webhook: true,  untagged: true  },
    harbor:  { label: "Harbor",                            fixedUrl: null,                    webhook: true,  untagged: true  },
    generic: { label: "Generic OCI Registry",              fixedUrl: null,                    webhook: true,  untagged: false },
};

const regTypeLabel = (t: string) => (t in TYPE_CAPS ? TYPE_CAPS[t as RegType].label : t);
type ScanMode = "webhook" | "poll" | "both";

type Visibility = "public" | "private";

type VerificationMode = "none" | "public_key" | "keyless";

interface RegistryFormState {
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

const emptyForm = (): RegistryFormState => ({
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

function toPatternArray(s: string): string[] {
    return s.split("\n").map(p => p.trim()).filter(p => p !== "");
}

/** One namespace's ingest channels, split by what there is to configure. */
interface NamespaceGroup {
    namespace: string;
    registries: Registry[];
    uploads: Source[];
}

export function SourcesTab() {
    const query = useListRegistries();
    const sourcesQuery = useListSources();
    const createReg = useCreateRegistry();
    const updateReg = useUpdateRegistry();
    const deleteReg = useDeleteRegistry();
    const testConn = useTestRegistryConnection();
    const scanReg = useScanRegistry();
    const regenSecret = useRegenerateWebhookSecret();
    const toast = useToast();
    const activeJobs = useListScanJobs(() => ({ limit: 100 }));
    const activeByRegistry = createMemo(() => {
        const counts = new Map<string, number>();
        for (const job of activeJobs.data?.data ?? []) {
            if ((job.state === "running" || job.state === "queued") && job.registry_id !== undefined) {
                counts.set(job.registry_id, (counts.get(job.registry_id) ?? 0) + 1);
            }
        }
        return counts;
    });

    const trustSummary = useRegistryTrustSummary();
    const trustByRegistry = createMemo(() => {
        const byRegistry = new Map<string, Map<string, number>>();
        for (const row of trustSummary.data?.data ?? []) {
            let statuses = byRegistry.get(row.registryId);
            if (statuses === undefined) {
                statuses = new Map<string, number>();
                byRegistry.set(row.registryId, statuses);
            }
            statuses.set(row.signingStatus, row.count);
        }
        return byRegistry;
    });

    // Namespace is the ownership axis (ADR-039), so it is the axis this list is
    // organised by. Registry rows join to their source on `id` — migration
    // 00053 made registry.id a foreign key *onto* source.id, so they are the
    // same value and no extra lookup is needed.
    const namespaceGroups = createMemo((): NamespaceGroup[] => {
        const registriesByID = new Map<string, Registry>();
        for (const reg of query.data?.data ?? []) {
            registriesByID.set(reg.id, reg);
        }

        const groups = new Map<string, NamespaceGroup>();
        const groupFor = (name: string): NamespaceGroup => {
            let g = groups.get(name);
            if (g === undefined) {
                g = { namespace: name, registries: [], uploads: [] };
                groups.set(name, g);
            }
            return g;
        };

        for (const src of sourcesQuery.data?.data ?? []) {
            // namespace_name is documented as list-only; fall back to the id so
            // a heading is never blank.
            const g = groupFor(src.namespace_name ?? src.namespace_id);
            const reg = registriesByID.get(src.id);
            if (src.kind === "oci_registry" && reg !== undefined) {
                g.registries.push(reg);
            } else if (src.kind === "upload") {
                g.uploads.push(src);
            }
        }

        return [...groups.values()].sort((a, b) => a.namespace.localeCompare(b.namespace));
    });

    const recentDrift = useRecentDrift(() => ({ limit: 20 }));

    const statusQuery = useGetSystemStatus();

    const [form, setForm] = createSignal<RegistryFormState>(emptyForm());
    const [testResult, setTestResult] = createSignal<{ reachable: boolean; message: string } | null>(null);
    const [editingID, setEditingID] = createSignal<string | null>(null);
    const [editEnabled, setEditEnabled] = createSignal(true);
    const [editManagedRef, setEditManagedRef] = createSignal<string | null>(null);
    const [revealedSecret, setRevealedSecret] = createSignal<string | null>(null);

    // An external controller reconciles its own spec over whatever is stored, so
    // a save here would be reverted within seconds. Locking the form is more
    // honest than accepting an edit that silently disappears.
    const editingManaged = () => editingID() !== null && editManagedRef() !== null;

    const showPollOptions = () =>
        statusQuery.data?.scanner.poller_enabled === true ||
        (editingID() !== null && (form().scanMode === "poll" || form().scanMode === "both"));
    let dialogRef: HTMLDialogElement | undefined;

    function closeDialog() {
        setForm(emptyForm());
        setEditingID(null);
        setEditEnabled(true);
        setEditManagedRef(null);
        setTestResult(null);
    }

    function openAdd() {
        closeDialog();
        dialogRef?.showModal();
    }

    function startEdit(reg: { id: string; name: string; type: string; url: string; insecure: boolean; has_secret: boolean; has_auth: boolean; enabled: boolean; repositories?: string[] | null; repository_patterns?: string[] | null; tag_patterns?: string[] | null; scan_mode?: string; poll_interval_minutes?: number; visibility?: string; include_untagged?: boolean; verification_mode?: string; trust_public_key?: string | null; trust_identity?: string | null; trust_issuer?: string | null; managed_by?: string | null; managed_ref?: string | null }) {
        setEditingID(reg.id);
        setEditEnabled(reg.enabled);
        // Fall back to the owner name when the ref is absent, so the dialog can
        // always say *something* about who owns a marked registry.
        const owner = reg.managed_by ?? "";
        setEditManagedRef(owner === "" ? null : (reg.managed_ref ?? owner));
        setForm({
            name: reg.name,
            type: reg.type as RegType,
            url: reg.url,
            insecure: reg.insecure,
            authUsername: "",
            authToken: "",
            repositories: (reg.repositories ?? []).join("\n"),
            repositoryPatterns: (reg.repository_patterns ?? []).join("\n"),
            tagPatterns: (reg.tag_patterns ?? []).join("\n"),
            scanMode: (reg.scan_mode ?? "webhook") as ScanMode,
            pollIntervalMinutes: reg.poll_interval_minutes ?? 60,
            visibility: (reg.visibility ?? "public") as Visibility,
            includeUntagged: reg.include_untagged ?? false,
            verificationMode: ["public_key", "keyless"].includes(reg.verification_mode ?? "") ? (reg.verification_mode as VerificationMode) : "none",
            trustPublicKey: reg.trust_public_key ?? "",
            trustIdentity: reg.trust_identity ?? "",
            trustIssuer: reg.trust_issuer ?? "",
        });
        dialogRef?.showModal();
    }

    function handleSubmit(e: Event) {
        e.preventDefault();
        const f = form();
        const authUsername = f.authUsername.trim() || undefined;
        const authToken = f.authToken.trim() || undefined;

        const repos = toPatternArray(f.repositories);
        const repoPats = toPatternArray(f.repositoryPatterns);
        const tagPats = toPatternArray(f.tagPatterns);

        const currentID = editingID();
        const trustPublicKey = f.verificationMode === "public_key" ? (f.trustPublicKey.trim() || undefined) : undefined;
        const trustIdentity = f.verificationMode === "keyless" ? (f.trustIdentity.trim() || undefined) : undefined;
        const trustIssuer = f.verificationMode === "keyless" ? (f.trustIssuer.trim() || undefined) : undefined;

        if (currentID !== null) {
            updateReg.mutate(
                { id: currentID, name: f.name, type: f.type, url: f.url, insecure: f.insecure, auth_username: authUsername, auth_token: authToken, enabled: editEnabled(), repositories: repos, repository_patterns: repoPats, tag_patterns: tagPats, scan_mode: f.scanMode, poll_interval_minutes: f.pollIntervalMinutes, visibility: f.visibility, include_untagged: f.includeUntagged, verification_mode: f.verificationMode, trust_public_key: trustPublicKey, trust_identity: trustIdentity, trust_issuer: trustIssuer },
                {
                    onSuccess: () => { toast("Registry updated", "success"); dialogRef?.close(); },
                    onError: () => toast("Failed to update registry", "error"),
                }
            );
        } else {
            createReg.mutate(
                { name: f.name, type: f.type, url: f.url, insecure: f.insecure, auth_username: authUsername, auth_token: authToken, repositories: repos, repository_patterns: repoPats, tag_patterns: tagPats, scan_mode: f.scanMode, poll_interval_minutes: f.pollIntervalMinutes, visibility: f.visibility, include_untagged: f.includeUntagged, verification_mode: f.verificationMode, trust_public_key: trustPublicKey, trust_identity: trustIdentity, trust_issuer: trustIssuer },
                {
                    onSuccess: (data) => {
                        toast("Registry created", "success");
                        dialogRef?.close();
                        if (data.webhook_secret !== undefined) {
                            setRevealedSecret(data.webhook_secret);
                        }
                    },
                    onError: () => toast("Failed to create registry", "error"),
                }
            );
        }
    }

    function copyWebhookURL(url: string) {
        void copyText(url).then(() => {
            toast("Webhook URL copied", "success");
        });
    }

    const hasWebhook = (reg: { scan_mode?: string; type: string }) =>
        reg.scan_mode !== "poll" && TYPE_CAPS[reg.type as RegType].webhook;

    const columns: Column<Registry>[] = [
        {
            header: "Name",
            render: (reg) => (
                <div style={{ display: "flex", "align-items": "center", gap: "0.4rem", "flex-wrap": "wrap" }}>
                    {reg.name}
                    <Show when={(reg.managed_by ?? "") !== ""}>
                        <span
                            class="badge"
                            style={{ "font-size": "0.7rem" }}
                            title={`Configured by ${reg.managed_by ?? ""}${(reg.managed_ref ?? "") === "" ? "" : ` (${reg.managed_ref ?? ""})`} — edits made here are reverted on the next reconcile`}
                        >
                            {reg.managed_by === "kubernetes" ? "Managed by Kubernetes" : `Managed by ${reg.managed_by ?? ""}`}
                        </span>
                    </Show>
                </div>
            ),
        },
        { header: "Type", render: (reg) => <code>{regTypeLabel(reg.type)}</code> },
        { header: "URL", render: (reg) => <code>{reg.url}</code> },
        { header: "Visibility", render: (reg) => <span class="badge">{reg.visibility}</span> },
        {
            header: "Owner",
            render: (reg) => (
                <span style={{ color: "var(--color-text-muted)", "font-size": "0.85rem" }}>
                    {reg.owner_username ?? "—"}
                </span>
            ),
        },
        {
            header: "Status",
            render: (reg) => (
                <span style={{ color: reg.enabled ? "var(--color-success)" : "var(--color-text-muted)" }}>
                    {reg.enabled ? "Enabled" : "Disabled"}
                </span>
            ),
        },
        {
            header: "Signing Status",
            render: (reg) => (
                <Show
                    when={(() => {
                        const s = trustByRegistry().get(reg.id);
                        return s !== undefined && s.size > 0 ? s : undefined;
                    })()}
                    fallback={<span style={{ color: "var(--color-text-muted)" }}>—</span>}
                >
                    {(statuses) => (
                        <div style={{ display: "flex", "flex-wrap": "wrap", gap: "0.3rem" }}>
                            <For each={[...statuses().entries()]}>
                                {([status, count]) => {
                                    const t = trustStatus(status);
                                    return (
                                        <span
                                            class={t !== null ? trustBadgeClass(t.variant) : "badge"}
                                            style={{ "font-size": "0.75rem" }}
                                            title={signingStatusLabel(status)}
                                        >
                                            {signingStatusLabel(status)}: {count}
                                        </span>
                                    );
                                }}
                            </For>
                        </div>
                    )}
                </Show>
            ),
        },
        { header: "Scan Mode", render: (reg) => <code>{reg.scan_mode}</code> },
        {
            header: "Webhook URL",
            render: (reg) => (
                <div style={{ display: "flex", gap: "0.3rem" }}>
                    <Show when={hasWebhook(reg)} fallback={<span style={{ color: "var(--color-text-muted)" }}>—</span>}>
                        <button
                            class="btn"
                            style={{ "font-size": "0.75rem", padding: "0.2rem 0.5rem" }}
                            onClick={() => copyWebhookURL(reg.webhook_url)}
                        >
                            Copy URL
                        </button>
                        <button
                            class="btn"
                            style={{ "font-size": "0.75rem", padding: "0.2rem 0.5rem" }}
                            title="Generate a new webhook secret (invalidates the old one)"
                            disabled={regenSecret.isPending}
                            onClick={() => regenSecret.mutate(reg.id, {
                                onSuccess: (data) => setRevealedSecret(data.webhook_secret),
                                onError: () => toast("Failed to regenerate secret", "error"),
                            })}
                        >
                            Regen Secret
                        </button>
                    </Show>
                </div>
            ),
        },
        {
            header: "",
            render: (reg) => (
                <div style={{ display: "flex", gap: "0.4rem" }}>
                    <button
                        class="btn"
                        onClick={() => startEdit(reg)}
                    >
                        Edit
                    </button>
                    <button
                        class="btn"
                        title="Scan new/changed images; already-scanned digests are skipped"
                        onClick={() => scanReg.mutate({ id: reg.id }, {
                            onSuccess: (data) => toast(data.message, "success"),
                            onError: () => toast("Failed to start scan", "error"),
                        })}
                        disabled={scanReg.isPending}
                    >
                        Scan
                    </button>
                    <button
                        class="btn"
                        title="Re-scan every image, including already-scanned digests (repopulates enrichment)"
                        onClick={() => {
                            if (!confirm("Force a full re-scan of every image in this registry, including digests already ingested? This re-pulls and re-scans everything.")) return;
                            scanReg.mutate({ id: reg.id, force: true }, {
                                onSuccess: (data) => toast(data.message, "success"),
                                onError: () => toast("Failed to start scan", "error"),
                            });
                        }}
                        disabled={scanReg.isPending}
                    >
                        Force
                    </button>
                    <Show when={(activeByRegistry().get(reg.id) ?? 0) > 0}>
                        <span class="badge" style={{ background: "var(--color-primary)", color: "#fff", "font-size": "0.75rem" }}>
                            {activeByRegistry().get(reg.id)} active
                        </span>
                    </Show>
                    <button
                        class="btn"
                        onClick={() => deleteReg.mutate(reg.id, {
                            onSuccess: () => toast("Registry deleted", "success"),
                            onError: () => toast("Failed to delete registry", "error"),
                        })}
                        disabled={deleteReg.isPending}
                    >
                        Delete
                    </button>
                </div>
            ),
        },
    ];

    return (
        <>
            <Show when={revealedSecret()}>
                <div class="card" style={{ "border-color": "var(--color-success)", "margin-bottom": "1rem" }}>
                    <p style={{ "margin-bottom": "0.5rem" }}>
                        <strong>Webhook secret.</strong> Copy it now — it will not be shown again.
                    </p>
                    <code style={{ "word-break": "break-all", display: "block", "margin-bottom": "0.5rem" }}>
                        {revealedSecret()}
                    </code>
                    <div style={{ display: "flex", gap: "0.5rem" }}>
                        <button class="btn btn-primary" onClick={() => {
                            void copyText(revealedSecret() ?? "").then(() => {
                                toast("Copied to clipboard", "success");
                            });
                        }}>
                            Copy
                        </button>
                        <button class="btn" onClick={() => setRevealedSecret(null)}>
                            Dismiss
                        </button>
                    </div>
                </div>
            </Show>

            <div style={{ "margin-bottom": "1rem" }}>
                <button class="btn btn-primary" onClick={openAdd}>Add Registry</button>
            </div>

            <dialog ref={dialogRef} onClose={closeDialog}>
                <div style={{ padding: "1.5rem" }}>
                <div class="card-header">
                    <h3>{editingID() !== null ? "Edit Registry" : "Add Registry"}</h3>
                </div>
                    <Show when={editingManaged()}>
                        <div
                            class="card"
                            data-testid="managed-notice"
                            style={{ "border-color": "var(--color-warning, #d69e2e)", "margin-bottom": "0.75rem", "font-size": "0.85rem" }}
                        >
                            This registry is configured by Kubernetes
                            (<code>{editManagedRef()}</code>). Its settings are reconciled from
                            the <code>OCIRegistry</code> resource, so changes saved here would be
                            overwritten. Edit the resource instead.
                        </div>
                    </Show>
                    <form onSubmit={handleSubmit}>
                    <fieldset disabled={editingManaged()} style={{ border: "none", padding: "0", margin: "0" }}>
                        <div style={{ display: "grid", "grid-template-columns": "1fr 1fr", gap: "0.75rem", "margin-bottom": "0.75rem" }}>
                            <div>
                                <label style={{ display: "block", "margin-bottom": "0.25rem", "font-size": "0.85rem" }}>Name</label>
                                <input
                                    type="text"
                                    value={form().name}
                                    onInput={(e) => setForm(f => ({ ...f, name: e.currentTarget.value }))}
                                    placeholder="my-registry"
                                    style={{ width: "100%" }}
                                    required
                                />
                            </div>
                            <div>
                                <label style={{ display: "block", "margin-bottom": "0.25rem", "font-size": "0.85rem" }}>Type</label>
                                <select
                                    value={form().type}
                                    onChange={(e) => {
                                        const newType = e.currentTarget.value as RegType;
                                        const caps = TYPE_CAPS[newType];
                                        setForm(f => ({
                                            ...f,
                                            type: newType,
                                            url: caps.fixedUrl ?? (newType === f.type ? f.url : ""),
                                            scanMode: !caps.webhook ? "poll" : f.scanMode,
                                            includeUntagged: caps.untagged ? f.includeUntagged : false,
                                        }));
                                    }}
                                    style={{ width: "100%" }}
                                >
                                    <For each={Object.entries(TYPE_CAPS) as [RegType, typeof TYPE_CAPS[RegType]][]}>{([type, caps]) => (
                                        <option value={type}>{caps.label}</option>
                                    )}</For>
                                </select>
                            </div>
                            <div>
                                <label style={{ display: "block", "margin-bottom": "0.25rem", "font-size": "0.85rem" }}>URL</label>
                                <div style={{ display: "flex", gap: "0.4rem" }}>
                                    <input
                                        type="text"
                                        value={form().url}
                                        onInput={(e) => { setForm(f => ({ ...f, url: e.currentTarget.value })); setTestResult(null); }}
                                        placeholder="registry:5000"
                                        style={{ flex: "1", ...(TYPE_CAPS[form().type].fixedUrl !== null ? { background: "var(--color-surface-2, #f0f0f0)", cursor: "not-allowed" } : {}) }}
                                        readOnly={TYPE_CAPS[form().type].fixedUrl !== null}
                                        required
                                    />
                                    <button
                                        type="button"
                                        class="btn"
                                        disabled={testConn.isPending || !form().url.trim()}
                                        onClick={() => {
                                            setTestResult(null);
                                            testConn.mutate(
                                                { url: form().url.trim(), insecure: form().insecure, auth_username: form().authUsername.trim() || undefined, auth_token: form().authToken.trim() || undefined },
                                                { onSuccess: (data) => setTestResult(data) }
                                            );
                                        }}
                                    >
                                        {testConn.isPending ? "Testing…" : "Test"}
                                    </button>
                                </div>
                                <Show when={testResult()}>
                                    <div style={{
                                        "margin-top": "0.3rem",
                                        "font-size": "0.8rem",
                                        color: testResult()?.reachable === true ? "var(--color-success)" : "var(--color-error, #e53e3e)",
                                    }}>
                                        {testResult()?.reachable === true ? "✓" : "✗"} {testResult()?.message}
                                    </div>
                                </Show>
                            </div>
                            <div>
                                <label style={{ display: "block", "margin-bottom": "0.25rem", "font-size": "0.85rem" }}>
                                    Auth Username <span style={{ color: "var(--color-text-muted)" }}>(optional; for registries requiring credentials)</span>
                                </label>
                                <input
                                    type="text"
                                    value={form().authUsername}
                                    onInput={(e) => setForm(f => ({ ...f, authUsername: e.currentTarget.value }))}
                                    placeholder={editingID() !== null ? "Leave blank to keep existing" : "Leave blank for anonymous"}
                                    style={{ width: "100%" }}
                                />
                            </div>
                            <div>
                                <label style={{ display: "block", "margin-bottom": "0.25rem", "font-size": "0.85rem" }}>
                                    Auth Token <span style={{ color: "var(--color-text-muted)" }}>(PAT or password; for registries requiring credentials)</span>
                                </label>
                                <input
                                    type="password"
                                    value={form().authToken}
                                    onInput={(e) => setForm(f => ({ ...f, authToken: e.currentTarget.value }))}
                                    placeholder={editingID() !== null ? "Leave blank to keep existing" : "Leave blank for anonymous"}
                                    style={{ width: "100%" }}
                                />
                            </div>
                            <div>
                                <label style={{ display: "block", "margin-bottom": "0.25rem", "font-size": "0.85rem" }}>
                                    Repositories {form().type === "ghcr"
                                        ? <span style={{ color: "var(--color-error, #e53e3e)", "font-weight": "bold" }}>(required for ghcr.io — catalog discovery is not supported)</span>
                                        : <span style={{ color: "var(--color-text-muted)" }}>(one per line; bypasses catalog discovery — required for ghcr.io, quay.io)</span>
                                    }
                                </label>
                                <textarea
                                    value={form().repositories}
                                    onInput={(e) => setForm(f => ({ ...f, repositories: e.currentTarget.value }))}
                                    placeholder={form().type === "ghcr" ? "my-org/my-image\nmy-org/other-image" : "buildah/buildah\nbuildah/buildah-testing"}
                                    rows={3}
                                    style={{ width: "100%", "font-family": "monospace", "font-size": "0.85rem" }}
                                />
                            </div>
                            <div>
                                <label style={{ display: "block", "margin-bottom": "0.25rem", "font-size": "0.85rem" }}>
                                    Repository Patterns <span style={{ color: "var(--color-text-muted)" }}>(one per line; filters catalog-discovered repos; empty = all)</span>
                                </label>
                                <textarea
                                    value={form().repositoryPatterns}
                                    onInput={(e) => setForm(f => ({ ...f, repositoryPatterns: e.currentTarget.value }))}
                                    placeholder={"my/project/**\nmy/other/app"}
                                    rows={3}
                                    style={{ width: "100%", "font-family": "monospace", "font-size": "0.85rem" }}
                                />
                            </div>
                            <div>
                                <label style={{ display: "block", "margin-bottom": "0.25rem", "font-size": "0.85rem" }}>
                                    Tag Patterns <span style={{ color: "var(--color-text-muted)" }}>(one per line; "semver" for semantic versions; empty = all)</span>
                                </label>
                                <textarea
                                    value={form().tagPatterns}
                                    onInput={(e) => setForm(f => ({ ...f, tagPatterns: e.currentTarget.value }))}
                                    placeholder={"semver\nlatest"}
                                    rows={3}
                                    style={{ width: "100%", "font-family": "monospace", "font-size": "0.85rem" }}
                                />
                            </div>
                            <div>
                                <label style={{ display: "block", "margin-bottom": "0.25rem", "font-size": "0.85rem" }}>Scan Mode</label>
                                <select
                                    value={form().scanMode}
                                    onChange={(e) => setForm(f => ({ ...f, scanMode: e.currentTarget.value as ScanMode }))}
                                    style={{ width: "100%" }}
                                    disabled={!TYPE_CAPS[form().type].webhook}
                                >
                                    <Show when={TYPE_CAPS[form().type].webhook}>
                                        <option value="webhook">Webhook</option>
                                    </Show>
                                    <option value="poll">Poll</option>
                                    <Show when={TYPE_CAPS[form().type].webhook}>
                                        <option value="both">Both</option>
                                    </Show>
                                </select>
                                <Show when={!TYPE_CAPS[form().type].webhook && !showPollOptions()}>
                                    <div style={{ "margin-top": "0.3rem", "font-size": "0.8rem", color: "var(--color-error, #e53e3e)" }}>
                                        Requires REGISTRY_POLLER_ENABLED=true — this registry type only supports polling.
                                    </div>
                                </Show>
                            </div>
                            <div>
                                <label style={{ display: "block", "margin-bottom": "0.25rem", "font-size": "0.85rem" }}>Visibility</label>
                                <select
                                    value={form().visibility}
                                    onChange={(e) => setForm(f => ({ ...f, visibility: e.currentTarget.value as Visibility }))}
                                    style={{ width: "100%" }}
                                >
                                    <option value="public">Public</option>
                                    <option value="private">Private</option>
                                </select>
                            </div>
                            <Show when={form().scanMode !== "webhook"}>
                                <div>
                                    <label style={{ display: "block", "margin-bottom": "0.25rem", "font-size": "0.85rem" }}>Poll Interval (minutes)</label>
                                    <input
                                        type="number"
                                        min={1}
                                        value={form().pollIntervalMinutes}
                                        onInput={(e) => setForm(f => ({ ...f, pollIntervalMinutes: parseInt(e.currentTarget.value, 10) || 60 }))}
                                        style={{ width: "100%" }}
                                    />
                                </div>
                            </Show>
                            <div>
                                <label style={{ display: "block", "margin-bottom": "0.25rem", "font-size": "0.85rem" }}>Verification Mode</label>
                                <select
                                    value={form().verificationMode}
                                    onChange={(e) => setForm(f => ({
                                        ...f,
                                        verificationMode: e.currentTarget.value as VerificationMode,
                                        trustPublicKey: e.currentTarget.value !== "public_key" ? "" : f.trustPublicKey,
                                        trustIdentity: e.currentTarget.value !== "keyless" ? "" : f.trustIdentity,
                                        trustIssuer: e.currentTarget.value !== "keyless" ? "" : f.trustIssuer,
                                    }))}
                                    style={{ width: "100%" }}
                                >
                                    <option value="none">None</option>
                                    <option value="public_key">Public Key</option>
                                    <option value="keyless">Keyless (Fulcio/Rekor)</option>
                                </select>
                            </div>
                            <Show when={form().verificationMode === "public_key"}>
                                <div style={{ "grid-column": "1 / -1" }}>
                                    <label style={{ display: "block", "margin-bottom": "0.25rem", "font-size": "0.85rem" }}>
                                        Trust Public Key (PEM)
                                    </label>
                                    <textarea
                                        value={form().trustPublicKey}
                                        onInput={(e) => setForm(f => ({ ...f, trustPublicKey: e.currentTarget.value }))}
                                        rows={6}
                                        placeholder={"-----BEGIN PUBLIC KEY-----\n..."}
                                        style={{ width: "100%", "font-family": "monospace", "font-size": "0.85rem" }}
                                    />
                                </div>
                            </Show>
                            <Show when={form().verificationMode === "keyless"}>
                                <div>
                                    <label style={{ display: "block", "margin-bottom": "0.25rem", "font-size": "0.85rem" }}>
                                        Trust Identity (SAN regex)
                                    </label>
                                    <input
                                        type="text"
                                        value={form().trustIdentity}
                                        onInput={(e) => setForm(f => ({ ...f, trustIdentity: e.currentTarget.value }))}
                                        placeholder="https://github.com/org/repo/.*"
                                        style={{ width: "100%", "font-family": "monospace", "font-size": "0.85rem" }}
                                    />
                                </div>
                                <div>
                                    <label style={{ display: "block", "margin-bottom": "0.25rem", "font-size": "0.85rem" }}>
                                        Trust Issuer
                                    </label>
                                    <input
                                        type="text"
                                        value={form().trustIssuer}
                                        onInput={(e) => setForm(f => ({ ...f, trustIssuer: e.currentTarget.value }))}
                                        placeholder="https://token.actions.githubusercontent.com"
                                        style={{ width: "100%", "font-family": "monospace", "font-size": "0.85rem" }}
                                    />
                                </div>
                            </Show>
                        </div>
                        <div style={{ display: "flex", gap: "1rem", "align-items": "center", "margin-bottom": "0.75rem" }}>
                            <label style={{ display: "flex", "align-items": "center", gap: "0.4rem", cursor: "pointer" }}>
                                <input
                                    type="checkbox"
                                    checked={form().insecure}
                                    onChange={(e) => setForm(f => ({ ...f, insecure: e.currentTarget.checked }))}
                                />
                                Allow insecure (HTTP)
                            </label>
                            <label style={{ display: "flex", "align-items": "center", gap: "0.4rem", cursor: TYPE_CAPS[form().type].untagged ? "pointer" : "not-allowed", opacity: TYPE_CAPS[form().type].untagged ? 1 : 0.4 }}>
                                <input
                                    type="checkbox"
                                    checked={form().includeUntagged}
                                    disabled={!TYPE_CAPS[form().type].untagged}
                                    onChange={(e) => setForm(f => ({ ...f, includeUntagged: e.currentTarget.checked }))}
                                />
                                Include untagged manifests
                            </label>
                            <Show when={editingID() !== null}>
                                <label style={{ display: "flex", "align-items": "center", gap: "0.4rem", cursor: "pointer" }}>
                                    <input
                                        type="checkbox"
                                        checked={editEnabled()}
                                        onChange={(e) => setEditEnabled(e.currentTarget.checked)}
                                    />
                                    Enabled
                                </label>
                            </Show>
                        </div>
                    </fieldset>
                        <div style={{ display: "flex", gap: "0.5rem" }}>
                            <button class="btn btn-primary" type="submit" disabled={createReg.isPending || updateReg.isPending || editingManaged()}>
                                {editingID() !== null ? "Save" : "Create"}
                            </button>
                            <button class="btn" type="button" onClick={() => dialogRef?.close()}>
                                Cancel
                            </button>
                        </div>
                    </form>
                </div>
            </dialog>

            <Show
                when={!sourcesQuery.isLoading && !query.isLoading && !sourcesQuery.isError && !query.isError}
                fallback={
                    <DataTable
                        columns={columns}
                        rows={undefined}
                        loading={sourcesQuery.isLoading || query.isLoading}
                        isError={sourcesQuery.isError || query.isError}
                        error={sourcesQuery.error ?? query.error}
                        emptyTitle="No sources found"
                    />
                }
            >
                <Show
                    when={namespaceGroups().length > 0}
                    fallback={
                        <DataTable
                            columns={columns}
                            rows={[]}
                            loading={false}
                            isError={false}
                            emptyTitle="No sources found"
                        />
                    }
                >
                    <For each={namespaceGroups()}>
                        {(group) => (
                            <div style={{ "margin-bottom": "1.5rem" }}>
                                <h3
                                    data-testid="namespace-heading"
                                    style={{ "font-size": "1rem", "margin-bottom": "0.5rem" }}
                                >
                                    {group.namespace}{" "}
                                    <span class="group-header-count">{group.registries.length + group.uploads.length}</span>
                                </h3>

                                <Show when={group.registries.length > 0}>
                                    <DataTable
                                        columns={columns}
                                        rows={group.registries}
                                        loading={false}
                                        isError={false}
                                        emptyTitle="No registries found"
                                    />
                                </Show>

                                {/* Upload sources have no OCI configuration at all — no URL,
                                    no scan mode, no webhook. Listing them in the registry table
                                    would be a row of em-dashes claiming those settings exist
                                    but are unset, so they get their own short list instead. */}
                                <Show when={group.uploads.length > 0}>
                                    <div class="card" style={{ "margin-top": group.registries.length > 0 ? "0.75rem" : "0" }}>
                                        <For each={group.uploads}>
                                            {(src) => (
                                                <div
                                                    data-testid="upload-source"
                                                    style={{ display: "flex", "align-items": "center", gap: "0.5rem", padding: "0.35rem 0" }}
                                                >
                                                    <span class="badge">upload</span>
                                                    <span>{src.name}</span>
                                                    <span style={{ color: "var(--color-text-muted)", "font-size": "0.85rem" }}>
                                                        SBOMs pushed to the API — nothing to configure
                                                    </span>
                                                </div>
                                            )}
                                        </For>
                                    </div>
                                </Show>
                            </div>
                        )}
                    </For>
                </Show>
            </Show>

            <div class="card" style={{ "margin-top": "1.5rem" }}>
                <div class="card-header">
                    <h3>Recent Provenance Drift</h3>
                </div>
                <p style={{ color: "var(--color-text-muted)", "font-size": "0.85rem", "margin-bottom": "0.75rem" }}>
                    Drift tracking is regression-only: it records when a re-verified artifact's
                    signing status gets worse (e.g. verified → verification failed). Recovery
                    transitions such as unsigned → verified are not recorded here.
                </p>
                <Show
                    when={(recentDrift.data?.data?.length ?? 0) > 0}
                    fallback={<p style={{ color: "var(--color-text-muted)" }}>No drift events recorded.</p>}
                >
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Detected</th>
                                <th>Registry</th>
                                <th>Artifact</th>
                                <th>Change</th>
                                <th>Reason</th>
                            </tr>
                        </thead>
                        <tbody>
                            <For each={recentDrift.data?.data ?? []}>
                                {(entry) => (
                                    <tr>
                                        <td style={{ "font-size": "0.85rem" }}>{formatDateTime(entry.detectedAt)}</td>
                                        <td>{entry.registryName ?? "—"}</td>
                                        <td>
                                            <A href={`/sboms/${entry.sbomId}`} style={{ "font-size": "0.85rem" }}>
                                                {entry.artifactName ?? entry.sbomId}
                                            </A>
                                        </td>
                                        <td style={{ "font-size": "0.85rem" }}>
                                            {signingStatusLabel(entry.previousStatus)} → {signingStatusLabel(entry.newStatus)}
                                        </td>
                                        <td style={{ color: "var(--color-text-muted)", "font-size": "0.85rem" }}>
                                            {driftReasonLabel(entry.reason)}
                                        </td>
                                    </tr>
                                )}
                            </For>
                        </tbody>
                    </table>
                </Show>
            </div>
        </>
    );
}
