import { For, Show, createSignal } from "solid-js";
import { useLocation, A } from "@solidjs/router";
import { copyText } from "~/utils/clipboard";
import { useAuth } from "~/context/auth";
import { useToast } from "~/context/toast";
import { Loading, ErrorBox } from "~/components/Feedback";
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
    const [revealedKey, setRevealedKey] = createSignal<string | null>(null);

    function handleCreate(e: Event) {
        e.preventDefault();
        const name = newKeyName().trim();
        if (!name) return;
        createKey.mutate(name, {
            onSuccess: (data) => {
                setNewKeyName("");
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
                <form onSubmit={handleCreate} style={{ display: "flex", gap: "0.5rem", "align-items": "center" }}>
                    <input
                        type="text"
                        placeholder="Token name"
                        value={newKeyName()}
                        onInput={(e) => setNewKeyName(e.currentTarget.value)}
                        style={{ flex: "1" }}
                    />
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

    return (
        <Show when={!query.isLoading} fallback={<Loading />}>
            <Show when={!query.isError} fallback={<ErrorBox error={query.error} />}>
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
            </Show>
        </Show>
    );
}

// ---------------------------------------------------------------------------
// Registries Tab
// ---------------------------------------------------------------------------

type RegType = "zot" | "harbor" | "docker" | "generic" | "ghcr";
type ScanMode = "webhook" | "poll" | "both";

interface RegistryFormState {
    name: string;
    type: RegType;
    url: string;
    insecure: boolean;
    webhookSecret: string;
    authUsername: string;
    authToken: string;
    repositories: string;       // newline-separated explicit repos
    repositoryPatterns: string; // newline-separated
    tagPatterns: string;        // newline-separated
    scanMode: ScanMode;
    pollIntervalMinutes: number;
}

const emptyForm = (): RegistryFormState => ({
    name: "",
    type: "generic",
    url: "",
    insecure: false,
    webhookSecret: "",
    authUsername: "",
    authToken: "",
    repositories: "",
    repositoryPatterns: "",
    tagPatterns: "",
    scanMode: "webhook",
    pollIntervalMinutes: 60,
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
    const toast = useToast();

    const [form, setForm] = createSignal<RegistryFormState>(emptyForm());
    const [testResult, setTestResult] = createSignal<{ reachable: boolean; message: string } | null>(null);
    const [editingID, setEditingID] = createSignal<string | null>(null);
    const [editEnabled, setEditEnabled] = createSignal(true);
    const [showForm, setShowForm] = createSignal(false);

    function resetForm() {
        setForm(emptyForm());
        setEditingID(null);
        setEditEnabled(true);
        setShowForm(false);
        setTestResult(null);
    }

    function startEdit(reg: { id: string; name: string; type: string; url: string; insecure: boolean; has_secret: boolean; has_auth: boolean; enabled: boolean; repositories?: string[] | null; repository_patterns?: string[] | null; tag_patterns?: string[] | null; scan_mode?: string; poll_interval_minutes?: number }) {
        setEditingID(reg.id);
        setEditEnabled(reg.enabled);
        setForm({
            name: reg.name,
            type: reg.type as RegType,
            url: reg.url,
            insecure: reg.insecure,
            webhookSecret: "",
            authUsername: "",
            authToken: "",
            repositories: (reg.repositories ?? []).join("\n"),
            repositoryPatterns: (reg.repository_patterns ?? []).join("\n"),
            tagPatterns: (reg.tag_patterns ?? []).join("\n"),
            scanMode: (reg.scan_mode ?? "webhook") as ScanMode,
            pollIntervalMinutes: reg.poll_interval_minutes ?? 60,
        });
        setShowForm(true);
    }

    function handleSubmit(e: Event) {
        e.preventDefault();
        const f = form();
        const secret = f.webhookSecret.trim() || undefined;
        const authUsername = f.authUsername.trim() || undefined;
        const authToken = f.authToken.trim() || undefined;

        const repos = toPatternArray(f.repositories);
        const repoPats = toPatternArray(f.repositoryPatterns);
        const tagPats = toPatternArray(f.tagPatterns);

        const currentID = editingID();
        if (currentID !== null) {
            updateReg.mutate(
                { id: currentID, name: f.name, type: f.type, url: f.url, insecure: f.insecure, webhook_secret: secret, auth_username: authUsername, auth_token: authToken, enabled: editEnabled(), repositories: repos, repository_patterns: repoPats, tag_patterns: tagPats, scan_mode: f.scanMode, poll_interval_minutes: f.pollIntervalMinutes },
                {
                    onSuccess: () => { toast("Registry updated", "success"); resetForm(); },
                    onError: () => toast("Failed to update registry", "error"),
                }
            );
        } else {
            createReg.mutate(
                { name: f.name, type: f.type, url: f.url, insecure: f.insecure, webhook_secret: secret, auth_username: authUsername, auth_token: authToken, repositories: repos, repository_patterns: repoPats, tag_patterns: tagPats, scan_mode: f.scanMode, poll_interval_minutes: f.pollIntervalMinutes },
                {
                    onSuccess: () => { toast("Registry created", "success"); resetForm(); },
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
            <Show when={showForm()}>
                <div class="card" style={{ "margin-bottom": "1rem" }}>
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
                                        setForm(f => ({
                                            ...f,
                                            type: newType,
                                            ...(newType === "ghcr" && !f.url ? { url: "ghcr.io" } : {}),
                                        }));
                                    }}
                                    style={{ width: "100%" }}
                                >
                                    <option value="generic">generic</option>
                                    <option value="ghcr">ghcr</option>
                                    <option value="zot">zot</option>
                                    <option value="harbor">harbor</option>
                                    <option value="docker">docker</option>
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
                                        style={{ flex: "1" }}
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
                                    Webhook Secret <span style={{ color: "var(--color-text-muted)" }}>(optional)</span>
                                </label>
                                <input
                                    type="password"
                                    value={form().webhookSecret}
                                    onInput={(e) => setForm(f => ({ ...f, webhookSecret: e.currentTarget.value }))}
                                    placeholder={editingID() !== null ? "Leave blank to keep existing" : "Leave blank to disable auth"}
                                    style={{ width: "100%" }}
                                />
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
                                >
                                    <option value="webhook">webhook</option>
                                    <option value="poll">poll</option>
                                    <option value="both">both</option>
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
                            <button class="btn" type="button" onClick={resetForm}>
                                Cancel
                            </button>
                        </div>
                    </form>
                </div>
            </Show>

            <Show when={!showForm()}>
                <div style={{ "margin-bottom": "1rem" }}>
                    <button class="btn btn-primary" onClick={() => setShowForm(true)}>
                        Add Registry
                    </button>
                </div>
            </Show>

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
                                        <th>Status</th>
                                        <th>Scan Mode</th>
                                        <th>Webhook URL</th>
                                        <th />
                                    </tr>
                                </thead>
                                <tbody>
                                    <For each={query.data?.registries ?? []}>
                                        {(reg) => (
                                            <tr>
                                                <td>{reg.name}</td>
                                                <td><code>{reg.type}</code></td>
                                                <td><code>{reg.url}</code></td>
                                                <td>
                                                    <span style={{ color: reg.enabled ? "var(--color-success)" : "var(--color-text-muted)" }}>
                                                        {reg.enabled ? "Enabled" : "Disabled"}
                                                    </span>
                                                </td>
                                                <td><code>{reg.scan_mode}</code></td>
                                                <td>
                                                    <button
                                                        class="btn"
                                                        style={{ "font-size": "0.75rem", padding: "0.2rem 0.5rem" }}
                                                        onClick={() => copyWebhookURL(reg.webhook_url)}
                                                    >
                                                        Copy URL
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
// Admin Page
// ---------------------------------------------------------------------------

export default function Admin() {
    const location = useLocation();
    const { user } = useAuth();

    const isUsersTab = () => location.pathname === "/admin";
    const isKeysTab = () => location.pathname === "/admin/keys";
    const isStatusTab = () => location.pathname === "/admin/status";
    const isRegistriesTab = () => location.pathname === "/admin/registries";

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
                <Show when={user()?.role === "admin"}>
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
                </Show>
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
        </>
    );
}
