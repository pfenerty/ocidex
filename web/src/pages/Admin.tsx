import { For, Show, createSignal, createMemo } from "solid-js";
import { useLocation, A } from "@solidjs/router";
import { VisXYContainer, VisLine, VisGroupedBar, VisAxis } from "@unovis/solid";
import { copyText } from "~/utils/clipboard";
import { useAuth } from "~/context/auth";
import { useToast } from "~/context/toast";
import { Loading, ErrorBox } from "~/components/Feedback";
import { formatDateTime } from "~/utils/format";
import type { CategoryCountEntry, DailyCountEntry } from "~/api/client";
import { CATEGORY_COLORS } from "~/utils/licenseUtils";
import {
    useListUsers,
    useUpdateUserRole,
    useListAPIKeys,
    useCreateAPIKey,
    useDeleteAPIKey,
    useGetSystemStatus,
    useListRegistries,
    useCreateRegistry,
    useUpdateRegistry,
    useDeleteRegistry,
    useTestRegistryConnection,
    useScanRegistry,
    useRegenerateWebhookSecret,
    useDashboardStats,
    useListScanJobs,
} from "~/api/queries";

// ---------------------------------------------------------------------------
// Users Tab
// ---------------------------------------------------------------------------

function UsersTab() {
    const { user: currentUser } = useAuth();
    const query = useListUsers();
    const updateRole = useUpdateUserRole();
    const toast = useToast();

    return (
        <Show when={!query.isLoading} fallback={<Loading />}>
            <Show when={!query.isError} fallback={<ErrorBox error={query.error} />}>
                <div class="card">
                    <div class="table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>Username</th>
                                    <th>Role</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <For each={query.data?.users ?? []}>
                                    {(u) => {
                                        const isSelf = () => u.id === currentUser()?.id;
                                        const [role, setRole] = createSignal(u.role as "admin" | "member" | "viewer");
                                        return (
                                            <tr>
                                                <td>{u.github_username}</td>
                                                <td>
                                                    <span class="badge">{role()}</span>
                                                </td>
                                                <td>
                                                    <select
                                                        value={role()}
                                                        disabled={isSelf() || updateRole.isPending}
                                                        onChange={(e) => {
                                                            const newRole = e.currentTarget.value as "admin" | "member" | "viewer";
                                                            setRole(newRole);
                                                            updateRole.mutate({ id: u.id, role: newRole }, {
                                                onSuccess: () => toast(`Role updated to ${newRole}`, "success"),
                                                onError: () => toast("Failed to update role", "error"),
                                            });
                                                        }}
                                                    >
                                                        <option value="admin">admin</option>
                                                        <option value="member">member</option>
                                                        <option value="viewer">viewer</option>
                                                    </select>
                                                </td>
                                            </tr>
                                        );
                                    }}
                                </For>
                            </tbody>
                        </table>
                    </div>
                </div>
            </Show>
        </Show>
    );
}

// ---------------------------------------------------------------------------
// API Keys Tab
// ---------------------------------------------------------------------------

function APIKeysTab() {
    const query = useListAPIKeys();
    const createKey = useCreateAPIKey();
    const deleteKey = useDeleteAPIKey();
    const toast = useToast();
    const [newKeyName, setNewKeyName] = createSignal("");
    const [newKeyScope, setNewKeyScope] = createSignal<"read" | "read-write">("read-write");
    const [revealedKey, setRevealedKey] = createSignal<string | null>(null);

    function handleCreate(e: Event) {
        e.preventDefault();
        const name = newKeyName().trim();
        if (!name) return;
        createKey.mutate({ name, scope: newKeyScope() }, {
            onSuccess: (data) => {
                setNewKeyName("");
                setNewKeyScope("read-write");
                setRevealedKey(data.key);
            },
            onError: () => toast("Failed to create API key", "error"),
        });
    }

    return (
        <>
            <Show when={revealedKey()}>
                <div class="card" style={{ "border-color": "var(--color-success)", "margin-bottom": "1rem" }}>
                    <p style={{ "margin-bottom": "0.5rem" }}>
                        <strong>API key created.</strong> Copy it now — it will not be shown again.
                    </p>
                    <code style={{ "word-break": "break-all", display: "block", "margin-bottom": "0.5rem" }}>
                        {revealedKey()}
                    </code>
                    <div style={{ display: "flex", gap: "0.5rem" }}>
                        <button class="btn btn-primary" onClick={() => {
                            void copyText(revealedKey() ?? "").then(() => {
                                toast("Copied to clipboard", "success");
                            });
                        }}>
                            Copy
                        </button>
                        <button class="btn" onClick={() => setRevealedKey(null)}>
                            Dismiss
                        </button>
                    </div>
                </div>
            </Show>

            <div class="card" style={{ "margin-bottom": "1rem" }}>
                <div class="card-header">
                    <h3>Create Bot Token</h3>
                </div>
                <form onSubmit={handleCreate} style={{ display: "flex", gap: "0.5rem", "align-items": "center", "flex-wrap": "wrap" }}>
                    <input
                        type="text"
                        placeholder="Token name"
                        value={newKeyName()}
                        onInput={(e) => setNewKeyName(e.currentTarget.value)}
                        style={{ flex: "1", "min-width": "12rem" }}
                    />
                    <select
                        value={newKeyScope()}
                        onChange={(e) => setNewKeyScope(e.currentTarget.value as "read" | "read-write")}
                    >
                        <option value="read-write">Read-write</option>
                        <option value="read">Read-only</option>
                    </select>
                    <button class="btn btn-primary" type="submit" disabled={createKey.isPending || !newKeyName().trim()}>
                        Create
                    </button>
                </form>
            </div>

            <Show when={!query.isLoading} fallback={<Loading />}>
                <Show when={!query.isError} fallback={<ErrorBox error={query.error} />}>
                    <div class="card">
                        <div class="table-wrapper">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Name</th>
                                        <th>Prefix</th>
                                        <th>Scope</th>
                                        <th>Created</th>
                                        <th>Last Used</th>
                                        <th />
                                    </tr>
                                </thead>
                                <tbody>
                                    <For each={query.data?.keys ?? []}>
                                        {(k) => (
                                            <tr>
                                                <td>{k.name}</td>
                                                <td>
                                                    <code>{k.prefix}…</code>
                                                </td>
                                                <td>
                                                    <span class={`badge ${k.scope === "read" ? "" : "badge-success"}`}>
                                                        {k.scope}
                                                    </span>
                                                </td>
                                                <td>{new Date(k.created_at).toLocaleDateString()}</td>
                                                <td>
                                                    {k.last_used_at !== undefined
                                                        ? new Date(k.last_used_at).toLocaleDateString()
                                                        : <span style={{ color: "var(--color-text-muted)" }}>Never</span>}
                                                </td>
                                                <td>
                                                    <button
                                                        class="btn"
                                                        onClick={() => deleteKey.mutate(k.id, {
                                                            onSuccess: () => toast("API key deleted", "success"),
                                                            onError: () => toast("Failed to delete API key", "error"),
                                                        })}
                                                        disabled={deleteKey.isPending}
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

// ---------------------------------------------------------------------------
// System Status Tab
// ---------------------------------------------------------------------------

function StatusTab() {
    const query = useGetSystemStatus();
    const registries = useListRegistries();
    const polledRegistries = () =>
        (registries.data?.data ?? []).filter(
            (r) => r.scan_mode === "poll" || r.scan_mode === "both"
        );

    return (
        <Show when={!query.isLoading} fallback={<Loading />}>
            <Show when={!query.isError} fallback={<ErrorBox error={query.error} />}>
                <div style={{ display: "flex", "flex-direction": "column", gap: "1.5rem" }}>

                    <div>
                        <div class="section-title" style={{ "margin-bottom": "0.75rem" }}>Services</div>
                        <div class="stats-grid">
                            <div class="stat-card">
                                <div class="stat-label">Enrichment</div>
                                <div class="stat-value" style={{ color: query.data?.enrichment.enabled === true ? "var(--color-success)" : "var(--color-text-muted)" }}>
                                    {query.data?.enrichment.enabled === true ? "Enabled" : "Disabled"}
                                </div>
                                <Show when={query.data?.enrichment.enabled === true}>
                                    <div style={{ "font-size": "0.8rem", "margin-top": "0.25rem", color: "var(--color-text-muted)" }}>
                                        {query.data?.enrichment.workers} workers · queue {query.data?.enrichment.queue_size}
                                    </div>
                                </Show>
                            </div>
                            <div class="stat-card">
                                <div class="stat-label">Scanner</div>
                                <div class="stat-value" style={{ color: query.data?.scanner.enabled === true ? "var(--color-success)" : "var(--color-text-muted)" }}>
                                    {query.data?.scanner.enabled === true ? "Enabled" : "Disabled"}
                                </div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-label">Poller</div>
                                <div class="stat-value" style={{ color: query.data?.scanner.poller_enabled === true ? "var(--color-success)" : "var(--color-text-muted)" }}>
                                    {query.data?.scanner.poller_enabled === true ? "Enabled" : "Disabled"}
                                </div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-label">NATS</div>
                                <div class="stat-value" style={{ color: query.data?.nats.enabled === true ? "var(--color-success)" : "var(--color-text-muted)" }}>
                                    {query.data?.nats.enabled === true ? "Enabled" : "Disabled"}
                                </div>
                                <Show when={query.data?.nats.enabled === true}>
                                    <div style={{ "font-size": "0.8rem", "margin-top": "0.25rem", color: "var(--color-text-muted)" }}>
                                        {query.data?.nats.url}
                                    </div>
                                </Show>
                            </div>
                        </div>
                    </div>

                    <div>
                        <div class="section-title" style={{ "margin-bottom": "0.75rem" }}>Scan Pipeline</div>
                        <div class="stats-grid">
                            <div class="stat-card">
                                <div class="stat-label">Queued</div>
                                <div class="stat-value" style={{ color: (query.data?.scan_jobs.queued ?? 0) > 0 ? "var(--color-warning)" : "inherit" }}>
                                    {query.data?.scan_jobs.queued ?? 0}
                                </div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-label">Running</div>
                                <div class="stat-value" style={{ color: (query.data?.scan_jobs.running ?? 0) > 0 ? "var(--color-success)" : "inherit" }}>
                                    {query.data?.scan_jobs.running ?? 0}
                                </div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-label">Succeeded (24 h)</div>
                                <div class="stat-value">{query.data?.scan_jobs.succeeded_24h ?? 0}</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-label">Failed (24 h)</div>
                                <div class="stat-value" style={{ color: (query.data?.scan_jobs.failed_24h ?? 0) > 0 ? "var(--color-error)" : "inherit" }}>
                                    {query.data?.scan_jobs.failed_24h ?? 0}
                                </div>
                            </div>
                        </div>
                    </div>

                    <div>
                        <div class="section-title" style={{ "margin-bottom": "0.75rem" }}>Infrastructure</div>
                        <div class="stats-grid">
                            <div class="stat-card">
                                <div class="stat-label">Database</div>
                                <div class="stat-value" style={{ color: query.data?.db.ok === true ? "var(--color-success)" : "var(--color-error)" }}>
                                    {query.data?.db.ok === true ? "OK" : "Error"}
                                </div>
                                <div style={{ "font-size": "0.8rem", "margin-top": "0.25rem", color: "var(--color-text-muted)" }}>
                                    {query.data?.db.latency_ms} ms
                                </div>
                            </div>
                        </div>
                    </div>

                    <Show when={polledRegistries().length > 0}>
                        <div>
                            <div class="section-title" style={{ "margin-bottom": "0.75rem" }}>Registry Polling</div>
                            <div class="card">
                                <div class="table-wrapper">
                                    <table>
                                        <thead>
                                            <tr>
                                                <th>Registry</th>
                                                <th>Scan Mode</th>
                                                <th>Last Polled</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <For each={polledRegistries()}>
                                                {(reg) => (
                                                    <tr>
                                                        <td>{reg.name}</td>
                                                        <td><span class="badge">{reg.scan_mode}</span></td>
                                                        <td style={{ color: reg.last_polled_at !== undefined ? "inherit" : "var(--color-text-muted)" }}>
                                                            {reg.last_polled_at !== undefined ? formatDateTime(reg.last_polled_at) : "Never"}
                                                        </td>
                                                    </tr>
                                                )}
                                            </For>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </Show>

                </div>
            </Show>
        </Show>
    );
}

// ---------------------------------------------------------------------------
// Registries Tab
// ---------------------------------------------------------------------------

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

function RegistriesTab() {
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

// ---------------------------------------------------------------------------
// Jobs Tab
// ---------------------------------------------------------------------------

const JOB_STATE_COLORS: Record<string, string> = {
    queued: "var(--color-text-muted)",
    running: "var(--color-primary)",
    succeeded: "var(--color-success)",
    failed: "var(--color-error, #e53e3e)",
};

const PAGE_SIZE = 20;

function JobsTab() {
    const [page, setPage] = createSignal(0);
    const [expandedErrors, setExpandedErrors] = createSignal(new Set<string>());
    const toggleError = (id: string) =>
        setExpandedErrors(prev => {
            const next = new Set(prev);
            if (next.has(id)) next.delete(id);
            else next.add(id);
            return next;
        });
    const query = useListScanJobs(() => ({ limit: PAGE_SIZE, offset: page() * PAGE_SIZE }));

    const total = () => query.data?.pagination.total ?? 0;
    const pageCount = () => Math.max(1, Math.ceil(total() / PAGE_SIZE));

    return (
        <Show when={!query.isLoading} fallback={<Loading />}>
            <Show when={!query.isError} fallback={<ErrorBox error={query.error} />}>
                <div class="card">
                    <div class="table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>State</th>
                                    <th>Repository</th>
                                    <th>Attempts</th>
                                    <th>Created</th>
                                    <th>Last Error</th>
                                    <th>SBOM</th>
                                </tr>
                            </thead>
                            <tbody>
                                <For each={query.data?.data ?? []}>
                                    {(job) => (
                                        <tr>
                                            <td>
                                                <span class="badge" style={{ color: JOB_STATE_COLORS[job.state] ?? "inherit" }}>
                                                    {job.state}
                                                </span>
                                            </td>
                                            <td>
                                                <code>{job.tag !== undefined ? `${job.repository}:${job.tag}` : job.repository}</code>
                                            </td>
                                            <td>{job.attempts}</td>
                                            <td style={{ "white-space": "nowrap" }}>{formatDateTime(job.created_at)}</td>
                                            <td>
                                                <Show when={job.last_error}>
                                                    <button
                                                        style={{ cursor: "pointer", "font-size": "0.85rem", background: "none", border: "none", padding: 0, color: "var(--color-primary)" }}
                                                        onClick={() => toggleError(job.id)}
                                                    >
                                                        {expandedErrors().has(job.id) ? "Hide error" : "View error"}
                                                    </button>
                                                    <Show when={expandedErrors().has(job.id)}>
                                                        <code style={{ "font-size": "0.8rem", "word-break": "break-all", display: "block", "margin-top": "0.25rem" }}>
                                                            {job.last_error}
                                                        </code>
                                                    </Show>
                                                </Show>
                                            </td>
                                            <td>
                                                <Show when={job.sbom_id}>
                                                    <A href={`/sboms/${job.sbom_id}`} style={{ "font-size": "0.85rem" }}>
                                                        View SBOM
                                                    </A>
                                                </Show>
                                            </td>
                                        </tr>
                                    )}
                                </For>
                            </tbody>
                        </table>
                    </div>
                    <Show when={pageCount() > 1}>
                        <div style={{ display: "flex", gap: "0.5rem", "align-items": "center", "margin-top": "1rem", "justify-content": "flex-end" }}>
                            <button class="btn" disabled={page() === 0} onClick={() => setPage(p => p - 1)}>Prev</button>
                            <span style={{ "font-size": "0.85rem" }}>Page {page() + 1} of {pageCount()}</span>
                            <button class="btn" disabled={page() + 1 >= pageCount()} onClick={() => setPage(p => p + 1)}>Next</button>
                        </div>
                    </Show>
                </div>
            </Show>
        </Show>
    );
}

// ---------------------------------------------------------------------------
// Metrics Tab
// ---------------------------------------------------------------------------

function GrowthChart(props: { data: DailyCountEntry[]; height?: number }) {
    const x = (_: DailyCountEntry, i: number) => i;
    const y = (d: DailyCountEntry) => d.count;
    const tickFormat = (tick: number | Date) => {
        const d = props.data[tick as number] as DailyCountEntry | undefined;
        return d?.day.slice(5) ?? "";
    };
    const numTicks = () => Math.min(props.data.length, 8);
    return (
        <VisXYContainer data={props.data} height={props.height ?? 180}>
            <VisLine x={x} y={y} />
            <VisAxis type="x" tickFormat={tickFormat} numTicks={numTicks()} />
            <VisAxis type="y" />
        </VisXYContainer>
    );
}

function MetricsTab() {
    const query = useDashboardStats();

    const cats = () => query.data?.license_categories ?? [];
    const timeline = () => query.data?.ingestion_timeline ?? [];
    const pkgGrowth = () => query.data?.package_growth_timeline ?? [];
    const verGrowth = () => query.data?.version_growth_timeline ?? [];
    const topPkgs = () => query.data?.top_packages ?? [];

    const catX = (_: CategoryCountEntry, i: number) => i;
    const catY = (d: CategoryCountEntry) => d.component_count;
    const catColor = (d: CategoryCountEntry) =>
        CATEGORY_COLORS[d.category]?.bg ?? "var(--color-secondary)";
    const catTickFormat = (tick: number | Date) =>
        cats()[tick as number]?.category ?? "";

    const ingestX = (_: DailyCountEntry, i: number) => i;
    const ingestY = (d: DailyCountEntry) => d.count;
    const ingestTickFormat = (tick: number | Date) => {
        const d = timeline()[tick as number] as DailyCountEntry | undefined;
        return d?.day.slice(5) ?? "";
    };

    return (
        <Show when={!query.isLoading} fallback={<Loading />}>
            <Show when={!query.isError} fallback={<ErrorBox error={query.error} />}>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-label">Artifacts</div>
                        <div class="stat-value">
                            <A href="/artifacts">{query.data?.artifact_count ?? 0}</A>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">SBOMs</div>
                        <div class="stat-value">{query.data?.sbom_count ?? 0}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Packages</div>
                        <div class="stat-value">
                            <A href="/components">{query.data?.package_count ?? 0}</A>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Package Versions</div>
                        <div class="stat-value">{query.data?.version_count ?? 0}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Licenses</div>
                        <div class="stat-value">
                            <A href="/licenses">{query.data?.license_count ?? 0}</A>
                        </div>
                    </div>
                </div>

                <div style={{ display: "grid", "grid-template-columns": "1fr 1fr", gap: "1rem", "margin-bottom": "1.5rem" }}>
                    <div class="card">
                        <div class="card-header">
                            <h3>Unique Packages Over Time</h3>
                        </div>
                        <Show
                            when={pkgGrowth().length > 0}
                            fallback={<p class="text-muted text-sm">No data yet</p>}
                        >
                            <GrowthChart data={pkgGrowth()} />
                        </Show>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h3>Unique Package Versions Over Time</h3>
                        </div>
                        <Show
                            when={verGrowth().length > 0}
                            fallback={<p class="text-muted text-sm">No data yet</p>}
                        >
                            <GrowthChart data={verGrowth()} />
                        </Show>
                    </div>
                </div>

                <div style={{ display: "grid", "grid-template-columns": "1fr 1fr", gap: "1rem", "margin-bottom": "1.5rem" }}>
                    <div class="card">
                        <div class="card-header">
                            <h3>License Categories</h3>
                        </div>
                        <Show
                            when={cats().length > 0}
                            fallback={<p class="text-muted text-sm">No license data</p>}
                        >
                            <VisXYContainer data={cats()} height={160}>
                                <VisGroupedBar x={catX} y={[catY]} color={catColor} />
                                <VisAxis type="x" tickFormat={catTickFormat} numTicks={cats().length} />
                                <VisAxis type="y" />
                            </VisXYContainer>
                        </Show>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h3>30-Day Ingestion</h3>
                        </div>
                        <Show
                            when={timeline().length > 0}
                            fallback={<p class="text-muted text-sm">No ingestion data</p>}
                        >
                            <VisXYContainer data={timeline()} height={160}>
                                <VisLine x={ingestX} y={ingestY} />
                                <VisAxis type="x" tickFormat={ingestTickFormat} numTicks={Math.min(timeline().length, 10)} />
                                <VisAxis type="y" />
                            </VisXYContainer>
                        </Show>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <h3>Top Packages by Version Count</h3>
                    </div>
                    <Show
                        when={topPkgs().length > 0}
                        fallback={<p class="text-muted text-sm">No packages yet</p>}
                    >
                        <div class="table-wrapper">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Package</th>
                                        <th>Type</th>
                                        <th>Versions</th>
                                        <th>SBOMs</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <For each={topPkgs()}>
                                        {(pkg) => (
                                            <tr>
                                                <td>
                                                    <A href={`/components/overview?name=${encodeURIComponent(pkg.name)}${pkg.group !== undefined && pkg.group !== "" ? `&group=${encodeURIComponent(pkg.group)}` : ""}`}>
                                                        {pkg.group !== undefined && pkg.group !== "" ? `${pkg.group}/${pkg.name}` : pkg.name}
                                                    </A>
                                                </td>
                                                <td><span class="badge">{pkg.type}</span></td>
                                                <td>{pkg.version_count}</td>
                                                <td>{pkg.sbom_count}</td>
                                            </tr>
                                        )}
                                    </For>
                                </tbody>
                            </table>
                        </div>
                    </Show>
                </div>
            </Show>
        </Show>
    );
}

// ---------------------------------------------------------------------------
// Admin Page
// ---------------------------------------------------------------------------

export default function Admin() {
    const location = useLocation();

    const isUsersTab = () => location.pathname === "/admin";
    const isKeysTab = () => location.pathname === "/admin/keys";
    const isStatusTab = () => location.pathname === "/admin/status";
    const isRegistriesTab = () => location.pathname === "/admin/registries";
    const isMetricsTab = () => location.pathname === "/admin/metrics";
    const isJobsTab = () => location.pathname === "/admin/jobs";

    return (
        <>
            <div class="page-header">
                <div class="page-header-row">
                    <div>
                        <h2>Admin</h2>
                        <p>User management, API keys, and system configuration</p>
                    </div>
                </div>
            </div>

            <nav style={{ display: "flex", gap: "0", "margin-bottom": "1.5rem", "border-bottom": "1px solid var(--color-border)" }}>
                <A
                    href="/admin"
                    style={{
                        padding: "0.5rem 1rem",
                        "border-bottom": isUsersTab() ? "2px solid var(--color-primary)" : "2px solid transparent",
                        color: isUsersTab() ? "var(--color-primary)" : "inherit",
                        "font-weight": isUsersTab() ? "600" : "400",
                        "margin-bottom": "-1px",
                    }}
                >
                    Users
                </A>
                <A
                    href="/admin/keys"
                    style={{
                        padding: "0.5rem 1rem",
                        "border-bottom": isKeysTab() ? "2px solid var(--color-primary)" : "2px solid transparent",
                        color: isKeysTab() ? "var(--color-primary)" : "inherit",
                        "font-weight": isKeysTab() ? "600" : "400",
                        "margin-bottom": "-1px",
                    }}
                >
                    API Keys
                </A>
                <A
                    href="/admin/registries"
                    style={{
                        padding: "0.5rem 1rem",
                        "border-bottom": isRegistriesTab() ? "2px solid var(--color-primary)" : "2px solid transparent",
                        color: isRegistriesTab() ? "var(--color-primary)" : "inherit",
                        "font-weight": isRegistriesTab() ? "600" : "400",
                        "margin-bottom": "-1px",
                    }}
                >
                    Registries
                </A>
                <A
                    href="/admin/status"
                    style={{
                        padding: "0.5rem 1rem",
                        "border-bottom": isStatusTab() ? "2px solid var(--color-primary)" : "2px solid transparent",
                        color: isStatusTab() ? "var(--color-primary)" : "inherit",
                        "font-weight": isStatusTab() ? "600" : "400",
                        "margin-bottom": "-1px",
                    }}
                >
                    System Status
                </A>
                <A
                    href="/admin/metrics"
                    style={{
                        padding: "0.5rem 1rem",
                        "border-bottom": isMetricsTab() ? "2px solid var(--color-primary)" : "2px solid transparent",
                        color: isMetricsTab() ? "var(--color-primary)" : "inherit",
                        "font-weight": isMetricsTab() ? "600" : "400",
                        "margin-bottom": "-1px",
                    }}
                >
                    Metrics
                </A>
                <A
                    href="/admin/jobs"
                    style={{
                        padding: "0.5rem 1rem",
                        "border-bottom": isJobsTab() ? "2px solid var(--color-primary)" : "2px solid transparent",
                        color: isJobsTab() ? "var(--color-primary)" : "inherit",
                        "font-weight": isJobsTab() ? "600" : "400",
                        "margin-bottom": "-1px",
                    }}
                >
                    Jobs
                </A>
            </nav>

            <Show when={isUsersTab()}>
                <UsersTab />
            </Show>
            <Show when={isKeysTab()}>
                <APIKeysTab />
            </Show>
            <Show when={isRegistriesTab()}>
                <RegistriesTab />
            </Show>
            <Show when={isStatusTab()}>
                <StatusTab />
            </Show>
            <Show when={isMetricsTab()}>
                <MetricsTab />
            </Show>
            <Show when={isJobsTab()}>
                <JobsTab />
            </Show>
        </>
    );
}
