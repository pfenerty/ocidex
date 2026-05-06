import { For, Show, createSignal, createMemo } from "solid-js";
import { copyText } from "~/utils/clipboard";
import { useToast } from "~/context/toast";
import { Loading, ErrorBox } from "~/components/Feedback";
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
});

function toPatternArray(s: string): string[] {
    return s.split("\n").map(p => p.trim()).filter(p => p !== "");
}

export function RegistriesTab() {
    const query = useListRegistries();
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

    const statusQuery = useGetSystemStatus();

    const [form, setForm] = createSignal<RegistryFormState>(emptyForm());
    const [testResult, setTestResult] = createSignal<{ reachable: boolean; message: string } | null>(null);
    const [editingID, setEditingID] = createSignal<string | null>(null);
    const [editEnabled, setEditEnabled] = createSignal(true);
    const [revealedSecret, setRevealedSecret] = createSignal<string | null>(null);

    const showPollOptions = () =>
        statusQuery.data?.scanner.poller_enabled === true ||
        (editingID() !== null && (form().scanMode === "poll" || form().scanMode === "both"));
    let dialogRef: HTMLDialogElement | undefined;

    function closeDialog() {
        setForm(emptyForm());
        setEditingID(null);
        setEditEnabled(true);
        setTestResult(null);
    }

    function openAdd() {
        closeDialog();
        dialogRef?.showModal();
    }

    function startEdit(reg: { id: string; name: string; type: string; url: string; insecure: boolean; has_secret: boolean; has_auth: boolean; enabled: boolean; repositories?: string[] | null; repository_patterns?: string[] | null; tag_patterns?: string[] | null; scan_mode?: string; poll_interval_minutes?: number; visibility?: string; include_untagged?: boolean }) {
        setEditingID(reg.id);
        setEditEnabled(reg.enabled);
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
        if (currentID !== null) {
            updateReg.mutate(
                { id: currentID, name: f.name, type: f.type, url: f.url, insecure: f.insecure, auth_username: authUsername, auth_token: authToken, enabled: editEnabled(), repositories: repos, repository_patterns: repoPats, tag_patterns: tagPats, scan_mode: f.scanMode, poll_interval_minutes: f.pollIntervalMinutes, visibility: f.visibility, include_untagged: f.includeUntagged },
                {
                    onSuccess: () => { toast("Registry updated", "success"); dialogRef?.close(); },
                    onError: () => toast("Failed to update registry", "error"),
                }
            );
        } else {
            createReg.mutate(
                { name: f.name, type: f.type, url: f.url, insecure: f.insecure, auth_username: authUsername, auth_token: authToken, repositories: repos, repository_patterns: repoPats, tag_patterns: tagPats, scan_mode: f.scanMode, poll_interval_minutes: f.pollIntervalMinutes, visibility: f.visibility, include_untagged: f.includeUntagged },
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
                    <form onSubmit={handleSubmit}>
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
                        <div style={{ display: "flex", gap: "0.5rem" }}>
                            <button class="btn btn-primary" type="submit" disabled={createReg.isPending || updateReg.isPending}>
                                {editingID() !== null ? "Save" : "Create"}
                            </button>
                            <button class="btn" type="button" onClick={() => dialogRef?.close()}>
                                Cancel
                            </button>
                        </div>
                    </form>
                </div>
            </dialog>

            <Show when={!query.isLoading} fallback={<Loading />}>
                <Show when={!query.isError} fallback={<ErrorBox error={query.error} />}>
                    <div class="card">
                        <div class="table-wrapper">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Name</th>
                                        <th>Type</th>
                                        <th>URL</th>
                                        <th>Visibility</th>
                                        <th>Owner</th>
                                        <th>Status</th>
                                        <th>Scan Mode</th>
                                        <th>Webhook URL</th>
                                        <th />
                                    </tr>
                                </thead>
                                <tbody>
                                    <For each={query.data?.data ?? []}>
                                        {(reg) => (
                                            <tr>
                                                <td>{reg.name}</td>
                                                <td><code>{regTypeLabel(reg.type)}</code></td>
                                                <td><code>{reg.url}</code></td>
                                                <td><span class="badge">{reg.visibility}</span></td>
                                                <td>
                                                    <span style={{ color: "var(--color-text-muted)", "font-size": "0.85rem" }}>
                                                        {reg.owner_username ?? "—"}
                                                    </span>
                                                </td>
                                                <td>
                                                    <span style={{ color: reg.enabled ? "var(--color-success)" : "var(--color-text-muted)" }}>
                                                        {reg.enabled ? "Enabled" : "Disabled"}
                                                    </span>
                                                </td>
                                                <td><code>{reg.scan_mode}</code></td>
                                                <td style={{ display: "flex", gap: "0.3rem" }}>
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
                                                </td>
                                                <td style={{ display: "flex", gap: "0.4rem" }}>
                                                    <button
                                                        class="btn"
                                                        onClick={() => startEdit(reg)}
                                                    >
                                                        Edit
                                                    </button>
                                                    <button
                                                        class="btn"
                                                        title="Scan all matching images in this registry"
                                                        onClick={() => scanReg.mutate(reg.id, {
                                                            onSuccess: (data) => toast(data.message, "success"),
                                                            onError: () => toast("Failed to start scan", "error"),
                                                        })}
                                                        disabled={scanReg.isPending}
                                                    >
                                                        Scan
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
                                                </td>
                                            </tr>
                                        )}
                                    </For>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </Show>
            </Show>
        </>
    );
}
