import { Show, createSignal, createMemo } from "solid-js";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { Card, CardHeader, FormField } from "~/components/ui";
import { useToast } from "~/context/toast";
import { relativeDate } from "~/utils/format";
import type { Namespace, Source } from "~/api/client";
import {
    useListNamespaces,
    useCreateNamespace,
    useUpdateNamespace,
    useDeleteNamespace,
    useListSources,
} from "~/api/queries";

type Visibility = "public" | "private";

/**
 * NamespacesTab is the management surface for the entity that owns every
 * artifact and governs visibility (ADR-039). Editing is inline rather than in a
 * dialog: a namespace has exactly two mutable fields, so a modal would be more
 * chrome than content.
 */
export function NamespacesTab() {
    const query = useListNamespaces();
    const sourcesQuery = useListSources();
    const createNamespace = useCreateNamespace();
    const updateNamespace = useUpdateNamespace();
    const deleteNamespace = useDeleteNamespace();
    const toast = useToast();

    const [newName, setNewName] = createSignal("");
    const [newVisibility, setNewVisibility] = createSignal<Visibility>("private");

    const [editingID, setEditingID] = createSignal<string | null>(null);
    const [editName, setEditName] = createSignal("");
    const [editVisibility, setEditVisibility] = createSignal<Visibility>("private");

    // How much a delete would take with it. The count is the honest version of
    // "and everything ingested under it" in the confirm prompt.
    const sourceCounts = createMemo(() => {
        const counts = new Map<string, number>();
        for (const src of (sourcesQuery.data?.data ?? []) as Source[]) {
            counts.set(src.namespace_id, (counts.get(src.namespace_id) ?? 0) + 1);
        }
        return counts;
    });

    function handleCreate(e: Event) {
        e.preventDefault();
        const name = newName().trim();
        if (name === "") return;
        createNamespace.mutate(
            { name, visibility: newVisibility() },
            {
                onSuccess: () => {
                    setNewName("");
                    setNewVisibility("private");
                    toast("Namespace created", "success");
                },
                onError: () => toast("Failed to create namespace", "error"),
            },
        );
    }

    function startEdit(ns: Namespace) {
        setEditingID(ns.id);
        setEditName(ns.name);
        setEditVisibility(ns.visibility);
    }

    function saveEdit(id: string) {
        const name = editName().trim();
        if (name === "") return;
        updateNamespace.mutate(
            { id, name, visibility: editVisibility() },
            {
                onSuccess: () => {
                    setEditingID(null);
                    toast("Namespace updated", "success");
                },
                onError: () => toast("Failed to update namespace", "error"),
            },
        );
    }

    function handleDelete(ns: Namespace) {
        const count = sourceCounts().get(ns.id) ?? 0;
        const scope =
            count > 0
                ? `${String(count)} source${count === 1 ? "" : "s"} and everything ingested under them`
                : "everything ingested under it";
        if (!confirm(`Delete namespace "${ns.name}"? This removes ${scope}. This cannot be undone.`)) {
            return;
        }
        deleteNamespace.mutate(ns.id, {
            onSuccess: () => toast("Namespace deleted", "success"),
            onError: () => toast("Failed to delete namespace", "error"),
        });
    }

    const columns: Column<Namespace>[] = [
        {
            header: "Name",
            sortKey: "name",
            sortValue: (ns) => ns.name,
            render: (ns) => (
                <Show when={editingID() === ns.id} fallback={<span>{ns.name}</span>}>
                    <input
                        type="text"
                        data-testid="edit-name"
                        value={editName()}
                        onInput={(e) => setEditName(e.currentTarget.value)}
                        style={{ "min-width": "10rem" }}
                    />
                </Show>
            ),
        },
        {
            header: "Visibility",
            sortKey: "visibility",
            sortValue: (ns) => ns.visibility,
            render: (ns) => (
                <Show
                    when={editingID() === ns.id}
                    fallback={
                        <span class={`badge ${ns.visibility === "public" ? "badge-success" : ""}`}>
                            {ns.visibility}
                        </span>
                    }
                >
                    <select
                        data-testid="edit-visibility"
                        value={editVisibility()}
                        onChange={(e) => setEditVisibility(e.currentTarget.value as Visibility)}
                    >
                        <option value="private">private</option>
                        <option value="public">public</option>
                    </select>
                </Show>
            ),
        },
        {
            header: "Owner",
            render: (ns) => (
                <Show
                    when={ns.owner_username ?? ns.owner_id}
                    fallback={<span style={{ color: "var(--color-text-muted)" }}>unowned</span>}
                >
                    {(owner) => <span>{owner()}</span>}
                </Show>
            ),
        },
        {
            header: "Sources",
            align: "right",
            sortKey: "sources",
            sortType: "numeric",
            sortValue: (ns) => sourceCounts().get(ns.id) ?? 0,
            render: (ns) => <>{sourceCounts().get(ns.id) ?? 0}</>,
        },
        {
            header: "Created",
            sortKey: "created",
            sortValue: (ns) => ns.created_at,
            render: (ns) => (
                <span title={new Date(ns.created_at).toLocaleString()}>{relativeDate(ns.created_at)}</span>
            ),
        },
        {
            header: "",
            render: (ns) => (
                <Show
                    when={editingID() === ns.id}
                    fallback={
                        <div style={{ display: "flex", gap: "0.5rem" }}>
                            <button class="btn btn-sm" onClick={() => startEdit(ns)}>
                                Edit
                            </button>
                            <button
                                class="btn btn-sm"
                                onClick={() => handleDelete(ns)}
                                disabled={deleteNamespace.isPending}
                            >
                                Delete
                            </button>
                        </div>
                    }
                >
                    <div style={{ display: "flex", gap: "0.5rem" }}>
                        <button
                            class="btn btn-sm btn-primary"
                            onClick={() => saveEdit(ns.id)}
                            disabled={updateNamespace.isPending || editName().trim() === ""}
                        >
                            Save
                        </button>
                        <button class="btn btn-sm" onClick={() => setEditingID(null)}>
                            Cancel
                        </button>
                    </div>
                </Show>
            ),
        },
    ];

    return (
        <>
            <Card style={{ "margin-bottom": "1rem" }}>
                <CardHeader title="Create Namespace" />
                <form
                    onSubmit={handleCreate}
                    style={{ display: "flex", gap: "0.75rem", "align-items": "flex-end", "flex-wrap": "wrap" }}
                >
                    <FormField label="Name">
                        <input
                            type="text"
                            placeholder="team-name"
                            value={newName()}
                            onInput={(e) => setNewName(e.currentTarget.value)}
                            style={{ "min-width": "14rem" }}
                        />
                    </FormField>
                    <FormField label="Visibility" hint="private is only visible to you and admins">
                        <select
                            value={newVisibility()}
                            onChange={(e) => setNewVisibility(e.currentTarget.value as Visibility)}
                        >
                            <option value="private">private</option>
                            <option value="public">public</option>
                        </select>
                    </FormField>
                    <button
                        class="btn btn-primary"
                        type="submit"
                        disabled={createNamespace.isPending || newName().trim() === ""}
                    >
                        Create
                    </button>
                </form>
            </Card>

            <DataTable
                columns={columns}
                rows={query.data?.data}
                loading={query.isLoading}
                isError={query.isError}
                error={query.error}
                emptyTitle="No namespaces found"
                emptyMessage="Every artifact is owned by a namespace. Create one to start ingesting under it."
            />
        </>
    );
}
