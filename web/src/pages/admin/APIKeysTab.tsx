import { For, Show, createSignal } from "solid-js";
import { copyText } from "~/utils/clipboard";
import { useToast } from "~/context/toast";
import { Loading, ErrorBox } from "~/components/Feedback";
import { useListAPIKeys, useCreateAPIKey, useDeleteAPIKey } from "~/api/queries";

export function APIKeysTab() {
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
