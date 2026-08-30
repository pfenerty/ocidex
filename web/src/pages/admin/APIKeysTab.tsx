import { For, Show, createSignal } from "solid-js";
import { copyText } from "~/utils/clipboard";
import { useToast } from "~/context/toast";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import type { APIKey, Capability } from "~/api/client";
import { useListAPIKeys, useCreateAPIKey, useDeleteAPIKey } from "~/api/queries";
import { Button, Card, CardHeader } from "~/components/ui";

/**
 * Every capability a key may declare, in the order the role table grants them:
 * read first, then the writes, then the two an owner alone holds. The type is
 * the generated one, so a capability added in Go fails to compile until it is
 * listed here.
 */
const CAPABILITIES: Capability[] = [
    "read_private",
    "ingest",
    "trigger_scan",
    "push_inventory",
    "delete_artifact",
    "manage_source",
    "manage_cluster",
    "read_secret",
    "manage_member",
    "delete_namespace",
];

/**
 * A key's capabilities are a ceiling, never a grant — the server intersects
 * them with the owner's live namespace roles on every request. "Full" therefore
 * does not mean "can do anything"; it means "can do whatever I can do", and it
 * keeps tracking that as the owner is promoted or demoted.
 */
type Preset = "full" | "read" | "custom";

const PRESETS: { value: Preset; label: string }[] = [
    { value: "full", label: "Everything my roles allow" },
    { value: "read", label: "Read-only" },
    { value: "custom", label: "Choose capabilities…" },
];

function capabilityLabel(c: string): string {
    return c.replace(/_/g, " ");
}

export function APIKeysTab() {
    const query = useListAPIKeys();
    const createKey = useCreateAPIKey();
    const deleteKey = useDeleteAPIKey();
    const toast = useToast();
    const [newKeyName, setNewKeyName] = createSignal("");
    const [preset, setPreset] = createSignal<Preset>("full");
    const [custom, setCustom] = createSignal<Capability[]>([]);
    const [revealedKey, setRevealedKey] = createSignal<string | null>(null);

    // An empty list is how the API spells "everything I may do", so the full
    // preset sends nothing rather than enumerating the ten — enumerating would
    // freeze the key against a capability added later.
    function requested(): Capability[] {
        switch (preset()) {
            case "full":
                return [];
            case "read":
                return ["read_private"];
            case "custom":
                return custom();
        }
    }

    function toggle(c: Capability, on: boolean) {
        setCustom((prev) => (on ? [...prev, c] : prev.filter((x) => x !== c)));
    }

    function handleCreate(e: Event) {
        e.preventDefault();
        const name = newKeyName().trim();
        if (!name) return;
        createKey.mutate({ name, capabilities: requested() }, {
            onSuccess: (data) => {
                setNewKeyName("");
                setPreset("full");
                setCustom([]);
                setRevealedKey(data.key);
            },
            onError: () => toast("Failed to create API key", "error"),
        });
    }

    const columns: Column<APIKey>[] = [
        { header: "Name", render: (k) => <>{k.name}</> },
        { header: "Prefix", render: (k) => <code>{k.prefix}…</code> },
        {
            header: "Capabilities",
            render: (k) => {
                const caps = k.capabilities ?? [];
                return (
                    <Show
                        when={caps.length < CAPABILITIES.length}
                        fallback={<span class="badge badge-success">all</span>}
                    >
                        <span class="flex gap-1" style={{ "flex-wrap": "wrap" }}>
                            <For each={caps}>
                                {(c) => <span class="badge">{capabilityLabel(c)}</span>}
                            </For>
                            <Show when={caps.length === 0}>
                                <span class="text-muted">none</span>
                            </Show>
                        </span>
                    </Show>
                );
            },
        },
        { header: "Created", render: (k) => <>{new Date(k.created_at).toLocaleDateString()}</> },
        {
            header: "Last Used",
            render: (k) =>
                k.last_used_at !== undefined
                    ? <>{new Date(k.last_used_at).toLocaleDateString()}</>
                    : <span class="text-muted">Never</span>,
        },
        {
            header: "",
            render: (k) => (
                <Button
                    onClick={() => deleteKey.mutate(k.id, {
                        onSuccess: () => toast("API key deleted", "success"),
                        onError: () => toast("Failed to delete API key", "error"),
                    })}
                    disabled={deleteKey.isPending}
                >
                    Delete
                </Button>
            ),
        },
    ];

    return (
        <>
            <Show when={revealedKey()}>
                <Card tone="success" class="mb-4">
                    <p style={{ "margin-bottom": "0.5rem" }}>
                        <strong>API key created.</strong> Copy it now — it will not be shown again.
                    </p>
                    <code style={{ "word-break": "break-all", display: "block", "margin-bottom": "0.5rem" }}>
                        {revealedKey()}
                    </code>
                    <div class="flex gap-2">
                        <Button variant="primary" onClick={() => {
                            void copyText(revealedKey() ?? "").then(() => {
                                toast("Copied to clipboard", "success");
                            });
                        }}>
                            Copy
                        </Button>
                        <Button onClick={() => setRevealedKey(null)}>
                            Dismiss
                        </Button>
                    </div>
                </Card>
            </Show>

            <Card class="mb-4">
                <CardHeader title="Create Bot Token" />
                <form onSubmit={handleCreate}>
                    <div style={{ display: "flex", gap: "0.5rem", "align-items": "center", "flex-wrap": "wrap" }}>
                        <input
                            type="text"
                            placeholder="Token name"
                            value={newKeyName()}
                            onInput={(e) => setNewKeyName(e.currentTarget.value)}
                            style={{ flex: "1", "min-width": "12rem" }}
                        />
                        <select
                            aria-label="Key capabilities"
                            value={preset()}
                            onChange={(e) => setPreset(e.currentTarget.value as Preset)}
                        >
                            <For each={PRESETS}>
                                {(p) => <option value={p.value}>{p.label}</option>}
                            </For>
                        </select>
                        <Button variant="primary" type="submit" disabled={createKey.isPending || !newKeyName().trim()}>
                            Create
                        </Button>
                    </div>
                    <Show when={preset() === "custom"}>
                        <fieldset
                            data-testid="capability-picker"
                            style={{ display: "flex", gap: "0.75rem", "flex-wrap": "wrap", "margin-top": "0.75rem", border: "none", padding: "0" }}
                        >
                            <For each={CAPABILITIES}>
                                {(c) => (
                                    <label class="flex gap-1" style={{ "align-items": "center" }}>
                                        <input
                                            type="checkbox"
                                            checked={custom().includes(c)}
                                            onChange={(e) => toggle(c, e.currentTarget.checked)}
                                        />
                                        {capabilityLabel(c)}
                                    </label>
                                )}
                            </For>
                        </fieldset>
                    </Show>
                    <p class="text-muted" style={{ "margin-top": "0.5rem", "margin-bottom": "0" }}>
                        A key can never exceed what its owner's namespace roles allow — narrowing a
                        member's role narrows every key they hold, with no key change.
                    </p>
                </form>
            </Card>

            <DataTable
                columns={columns}
                rows={query.data?.keys ?? undefined}
                loading={query.isFetching}
                isError={query.isError}
                error={query.error}
                emptyTitle="No API keys found"
            />
        </>
    );
}
