import { For, Show, createSignal } from "solid-js";
import { A } from "@solidjs/router";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { Card, CardHeader, FormField, StatusPill } from "~/components/ui";
import { useToast } from "~/context/toast";
import { relativeDate } from "~/utils/format";
import type { Cluster } from "~/api/client";
import {
    useListClusters,
    useCreateCluster,
    useUpdateCluster,
    useDeleteCluster,
    useMyNamespaces,
} from "~/api/queries";

/**
 * StalenessPill renders when an agent last reported, and it is deliberately the
 * loudest thing in the row.
 *
 * A cluster with no recent snapshot shows its *last* inventory, which looks
 * exactly like a current one. ADR-044 K5 is the rule this follows: an absence of
 * data must never read as an assertion of safety, so "never reported" and
 * "stale" are stated as warnings rather than left to be inferred from a
 * timestamp the reader has to do arithmetic on.
 *
 * The threshold is generous relative to the chart's 5m default reportInterval —
 * a missed cycle or two is a blip, an hour of silence is a broken agent.
 */
const STALE_AFTER_MS = 60 * 60 * 1000;

export function StalenessPill(props: { lastSeenAt: string | undefined }) {
    const seen = () => (props.lastSeenAt ?? "") !== "" ? props.lastSeenAt : undefined;
    const isStale = () => {
        const s = seen();
        if (s === undefined) return false;
        return Date.now() - new Date(s).getTime() > STALE_AFTER_MS;
    };
    return (
        <Show
            when={seen()}
            fallback={
                <StatusPill variant="warning" title="No agent has ever pushed a snapshot for this cluster">
                    never reported
                </StatusPill>
            }
        >
            {(s) => (
                <Show
                    when={isStale()}
                    fallback={<span title={new Date(s()).toLocaleString()}>{relativeDate(s())}</span>}
                >
                    <StatusPill
                        variant="warning"
                        title={`Last snapshot ${new Date(s()).toLocaleString()} — the inventory below may not be what is running now`}
                    >
                        stale · {relativeDate(s())}
                    </StatusPill>
                </Show>
            )}
        </Show>
    );
}

/**
 * Clusters is the registration and management surface for the Kubernetes
 * clusters an agent reports into (ADR-044).
 *
 * Not an Admin tab, unlike namespaces and sources: a cluster is owned by its
 * namespace and managed by whoever owns that namespace (K8 reuses ClassOwner,
 * not a site-admin role), and the Admin section is only rendered for
 * `role === "admin"`. Putting it there would lock every namespace owner out of
 * their own fleet.
 */
export default function Clusters() {
    const query = useListClusters();
    const namespacesQuery = useMyNamespaces();
    const createCluster = useCreateCluster();
    const updateCluster = useUpdateCluster();
    const deleteCluster = useDeleteCluster();
    const toast = useToast();

    const [newName, setNewName] = createSignal("");
    const [newNamespace, setNewNamespace] = createSignal("");
    const [newDescription, setNewDescription] = createSignal("");

    const [editingID, setEditingID] = createSignal<string | null>(null);
    const [editName, setEditName] = createSignal("");
    const [editDescription, setEditDescription] = createSignal("");
    const [editAutoIngest, setEditAutoIngest] = createSignal(true);

    function handleCreate(e: Event) {
        e.preventDefault();
        const name = newName().trim();
        const namespaceID = newNamespace();
        if (name === "" || namespaceID === "") return;
        const description = newDescription().trim();
        createCluster.mutate(
            { namespace_id: namespaceID, name, ...(description === "" ? {} : { description }) },
            {
                onSuccess: () => {
                    setNewName("");
                    setNewDescription("");
                    toast("Cluster registered — install the agent with its cluster ID", "success");
                },
                onError: () => toast("Failed to register cluster", "error"),
            },
        );
    }

    function startEdit(c: Cluster) {
        setEditingID(c.id);
        setEditName(c.name);
        setEditDescription(c.description ?? "");
        setEditAutoIngest(c.auto_ingest);
    }

    function saveEdit(id: string) {
        const name = editName().trim();
        if (name === "") return;
        updateCluster.mutate(
            { id, name, description: editDescription().trim(), auto_ingest: editAutoIngest() },
            {
                onSuccess: () => {
                    setEditingID(null);
                    toast("Cluster updated", "success");
                },
                onError: () => toast("Failed to update cluster", "error"),
            },
        );
    }

    function handleDelete(c: Cluster) {
        if (
            !confirm(
                `Delete cluster "${c.name}"? Its recorded inventory goes with it. The agent will start failing until it is pointed at a new cluster ID.`,
            )
        ) {
            return;
        }
        deleteCluster.mutate(c.id, {
            onSuccess: () => toast("Cluster deleted", "success"),
            onError: () => toast("Failed to delete cluster", "error"),
        });
    }

    const columns: Column<Cluster>[] = [
        {
            header: "Cluster",
            sortKey: "name",
            sortValue: (c) => c.name,
            render: (c) => (
                <Show
                    when={editingID() === c.id}
                    fallback={<A href={`/clusters/${c.id}`}>{c.name}</A>}
                >
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
            header: "Namespace",
            sortKey: "namespace",
            sortValue: (c) => c.namespace_name ?? "",
            render: (c) => <span class="text-muted">{c.namespace_name ?? "—"}</span>,
        },
        {
            header: "Description",
            render: (c) => (
                <Show
                    when={editingID() === c.id}
                    fallback={<span class="text-muted">{c.description ?? "—"}</span>}
                >
                    <input
                        type="text"
                        data-testid="edit-description"
                        value={editDescription()}
                        onInput={(e) => setEditDescription(e.currentTarget.value)}
                        style={{ "min-width": "12rem" }}
                    />
                </Show>
            ),
        },
        {
            // Read-only outside edit mode: flipping ingest on for a cluster is
            // a decision to spend that namespace's registry credentials, so it
            // goes through the same Save as a rename rather than firing off a
            // stray click in a table.
            header: "Auto-ingest",
            render: (c) => (
                <Show
                    when={editingID() === c.id}
                    fallback={
                        <span class="text-muted">{c.auto_ingest ? "On" : "Off"}</span>
                    }
                >
                    <label style={{ display: "flex", gap: "0.375rem", "align-items": "center" }}>
                        <input
                            type="checkbox"
                            data-testid="edit-auto-ingest"
                            checked={editAutoIngest()}
                            onChange={(e) => setEditAutoIngest(e.currentTarget.checked)}
                        />
                        <span class="text-muted text-sm">scan unknown images on push</span>
                    </label>
                </Show>
            ),
        },
        {
            header: "Last reported",
            sortKey: "last_seen",
            sortValue: (c) => c.last_seen_at ?? "",
            render: (c) => <StalenessPill lastSeenAt={c.last_seen_at} />,
        },
        {
            header: "",
            render: (c) => (
                <Show
                    when={editingID() === c.id}
                    fallback={
                        <div class="flex gap-2">
                            <button class="btn btn-sm" onClick={() => startEdit(c)}>
                                Edit
                            </button>
                            <button
                                class="btn btn-sm"
                                onClick={() => handleDelete(c)}
                                disabled={deleteCluster.isPending}
                            >
                                Delete
                            </button>
                        </div>
                    }
                >
                    <div class="flex gap-2">
                        <button
                            class="btn btn-sm btn-primary"
                            onClick={() => saveEdit(c.id)}
                            disabled={updateCluster.isPending || editName().trim() === ""}
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
            <div class="page-header">
                <div class="page-header-row">
                    <div>
                        <h2>Clusters</h2>
                        <p>
                            Kubernetes clusters reporting what they run. Register a cluster here,
                            then install the agent chart in it with the cluster ID.
                        </p>
                    </div>
                </div>
            </div>

            <Card class="mb-4">
                <CardHeader title="Register cluster" />
                <form
                    onSubmit={handleCreate}
                    style={{ display: "flex", gap: "0.75rem", "align-items": "flex-end", "flex-wrap": "wrap" }}
                >
                    <FormField label="Name">
                        <input
                            type="text"
                            placeholder="prod-eu-west"
                            value={newName()}
                            onInput={(e) => setNewName(e.currentTarget.value)}
                            class="min-w-56"
                        />
                    </FormField>
                    <FormField label="Namespace" hint="who owns the cluster and can see its inventory">
                        <select
                            value={newNamespace()}
                            onChange={(e) => setNewNamespace(e.currentTarget.value)}
                        >
                            <option value="">select…</option>
                            <For each={namespacesQuery.data?.data ?? []}>
                                {(ns) => <option value={ns.id}>{ns.name}</option>}
                            </For>
                        </select>
                    </FormField>
                    <FormField label="Description">
                        <input
                            type="text"
                            placeholder="optional"
                            value={newDescription()}
                            onInput={(e) => setNewDescription(e.currentTarget.value)}
                            class="min-w-56"
                        />
                    </FormField>
                    <button
                        class="btn btn-primary"
                        type="submit"
                        disabled={
                            createCluster.isPending || newName().trim() === "" || newNamespace() === ""
                        }
                    >
                        Register
                    </button>
                </form>
            </Card>

            <DataTable
                columns={columns}
                rows={query.data?.data}
                loading={query.isLoading}
                isError={query.isError}
                error={query.error}
                emptyTitle="No clusters registered"
                emptyMessage="Register a cluster, then install charts/ocidex-k8s-agent in it to start reporting the images it runs."
            />
        </>
    );
}
