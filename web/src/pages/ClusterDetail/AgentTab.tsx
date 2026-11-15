import { Show, createEffect, createMemo, createSignal } from "solid-js";
import { useNavigate } from "@solidjs/router";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { Button, Card, CardHeader, FormField, StatusPill } from "~/components/ui";
import { TimestampCell } from "~/components/cells";
import { useToast } from "~/context/toast";
import type { Cluster } from "~/api/client";
import type { components } from "~/types/openapi";
import { useClusterPushes, useDeleteCluster, useListNamespaces, useUpdateCluster } from "~/api/queries";
import { AgentCredentials } from "./AgentCredentials";
import { RetireClusterDialog } from "../RetireClusterDialog";

type Push = components["schemas"]["ClusterPushResponse"];

const pushColumns: Column<Push>[] = [
    { header: "When", render: (p) => <TimestampCell iso={p.at} /> },
    {
        header: "Result",
        render: (p) => (
            <StatusPill variant={p.accepted ? "success" : "danger"}>
                {p.accepted ? "accepted" : String(p.status)}
            </StatusPill>
        ),
    },
    {
        header: "Detail",
        class: "col-ref",
        render: (p) =>
            p.accepted ? (
                <span class="text-muted">
                    {(p.workloads ?? 0).toLocaleString()} containers
                    <Show when={p.agentVersion}>{(v) => <> · {v()}</>}</Show>
                </span>
            ) : (
                <span class="cluster-health-reason">{p.reason}</span>
            ),
    },
];

/**
 * AgentTab gathers everything about operating the agent (ocidex-70eo.7,
 * design Q2): the push history that explains the cluster's health, the
 * credentials it pushes with, the cluster's settings, and how to retire it.
 * These used to be split across the list row, the Overview and API keys.
 */
export function AgentTab(props: { cluster: Cluster }) {
    const toast = useToast();
    const navigate = useNavigate();
    const pushes = useClusterPushes(() => props.cluster.id);
    const update = useUpdateCluster();
    const del = useDeleteCluster();
    const namespaces = useListNamespaces();
    const canManage = createMemo(() =>
        ((namespaces.data?.data ?? []).find((n) => n.id === props.cluster.namespaceId)?.capabilities ?? []).includes(
            "manage_cluster",
        ),
    );

    const [name, setName] = createSignal("");
    const [description, setDescription] = createSignal("");
    const [autoIngest, setAutoIngest] = createSignal(true);
    // Reset the form when another cluster is shown, not on every poll.
    let shownId = "";
    createEffect(() => {
        if (props.cluster.id === shownId) return;
        shownId = props.cluster.id;
        setName(props.cluster.name);
        setDescription(props.cluster.description ?? "");
        setAutoIngest(props.cluster.autoIngest);
    });

    let retireRef: HTMLDialogElement | undefined;

    function save(e: Event) {
        e.preventDefault();
        update.mutate(
            { id: props.cluster.id, name: name().trim(), description: description().trim(), autoIngest: autoIngest() },
            {
                onSuccess: () => toast("Cluster updated", "success"),
                onError: () => toast("Failed to update cluster", "error"),
            },
        );
    }

    function setPaused(paused: boolean) {
        update.mutate(
            { id: props.cluster.id, name: props.cluster.name, description: props.cluster.description, paused },
            {
                onSuccess: () => {
                    toast(paused ? "Cluster paused" : "Cluster resumed", "success");
                    retireRef?.close();
                },
                onError: () => toast(paused ? "Failed to pause cluster" : "Failed to resume cluster", "error"),
            },
        );
    }

    return (
        <div class="agent-tab-grid">
            <Card>
                <CardHeader title="Recent pushes" />
                <DataTable
                    columns={pushColumns}
                    rows={pushes.data}
                    loading={pushes.isFetching && pushes.data === undefined}
                    isError={pushes.isError}
                    error={pushes.error}
                    emptyTitle="No pushes yet"
                    emptyMessage="Every push the agent makes appears here, refused ones with the reason."
                />
            </Card>

            <AgentCredentials clusterId={props.cluster.id} namespaceId={props.cluster.namespaceId} />

            <Show when={canManage()}>
                <Card>
                    <CardHeader title="Settings" />
                    <form onSubmit={save} class="grid gap-3">
                        <FormField label="Name">
                            <input
                                id="agent-settings-name"
                                type="text"
                                value={name()}
                                onInput={(e) => setName(e.currentTarget.value)}
                            />
                        </FormField>
                        <FormField label="Description">
                            <input
                                id="agent-settings-description"
                                type="text"
                                value={description()}
                                onInput={(e) => setDescription(e.currentTarget.value)}
                            />
                        </FormField>
                        <label class="flex items-center gap-2">
                            <input
                                id="agent-settings-auto-ingest"
                                type="checkbox"
                                checked={autoIngest()}
                                onChange={(e) => setAutoIngest(e.currentTarget.checked)}
                            />
                            Scan running images that have no SBOM
                        </label>
                        <p class="text-muted text-sm mb-0">
                            Namespace <strong>{props.cluster.namespaceName}</strong> is fixed: moving a cluster would
                            change who can see everything it has reported.
                        </p>
                        <div>
                            <Button variant="primary" type="submit" disabled={update.isPending || name().trim() === ""}>
                                Save
                            </Button>
                        </div>
                    </form>
                </Card>

                <Card class="agent-danger">
                    <CardHeader title="Pause or retire" />
                    <Show
                        when={props.cluster.pausedAt === undefined}
                        fallback={
                            <>
                                <p class="text-muted">
                                    Paused: pushes are refused and the last inventory is kept.
                                </p>
                                <div class="flex gap-2">
                                    <Button disabled={update.isPending} onClick={() => setPaused(false)}>
                                        Resume
                                    </Button>
                                    <Button onClick={() => retireRef?.showModal()}>Retire…</Button>
                                </div>
                            </>
                        }
                    >
                        <p class="text-muted">
                            Pause to stop accepting pushes but keep everything, or delete the cluster with its
                            inventory and credentials.
                        </p>
                        <div>
                            <Button onClick={() => retireRef?.showModal()}>Retire…</Button>
                        </div>
                    </Show>
                </Card>

                <RetireClusterDialog
                    ref={(el) => (retireRef = el)}
                    cluster={props.cluster}
                    busy={update.isPending || del.isPending}
                    onPause={() => setPaused(true)}
                    onDelete={(c) =>
                        del.mutate(c.id, {
                            onSuccess: () => {
                                toast("Cluster deleted", "success");
                                retireRef?.close();
                                navigate("/clusters");
                            },
                            onError: () => toast("Failed to delete cluster", "error"),
                        })
                    }
                    onCancel={() => retireRef?.close()}
                />
            </Show>

        </div>
    );
}
