import { For, Show, createSignal } from "solid-js";
import { useLocation, A } from "@solidjs/router";
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
                            const key = revealedKey() ?? "";
                            void navigator.clipboard.writeText(key);
                            toast("Copied to clipboard", "success");
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
// Admin Page
// ---------------------------------------------------------------------------

export default function Admin() {
    const location = useLocation();

    const isUsersTab = () => location.pathname === "/admin";
    const isKeysTab = () => location.pathname === "/admin/keys";
    const isStatusTab = () => location.pathname === "/admin/status";

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
            <Show when={isStatusTab()}>
                <StatusTab />
            </Show>
        </>
    );
}
