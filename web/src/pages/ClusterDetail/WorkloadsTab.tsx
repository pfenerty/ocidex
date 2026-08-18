import { Show } from "solid-js";
import { A } from "@solidjs/router";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { relativeDate, shortDigest } from "~/utils/format";
import { imageRefName } from "~/utils/oci";
import type { ClusterWorkload } from "~/api/client";
import { MatchStatePill } from "./matchState";

export const workloadColumns: Column<ClusterWorkload>[] = [
    {
        header: "Namespace",
        sortKey: "k8s_namespace",
        sortValue: (w) => w.k8s_namespace,
        render: (w) => <span class="text-muted">{w.k8s_namespace}</span>,
    },
    {
        header: "Workload",
        sortKey: "workload_name",
        sortValue: (w) => w.workload_name,
        render: (w) => (
            <span>
                {w.workload_name}
                <span class="text-muted"> · {w.workload_kind}</span>
            </span>
        ),
    },
    {
        header: "Container",
        sortKey: "container_name",
        sortValue: (w) => w.container_name,
        render: (w) => <span>{w.container_name}</span>,
    },
    {
        header: "Image",
        sortKey: "image_ref",
        sortValue: (w) => w.image_ref,
        render: (w) => (
            <span class="font-mono text-sm" title={w.image_digest ?? w.image_ref}>
                <Show
                    when={imageRefName(w.image_ref)}
                    fallback={<span class="text-muted italic">name not reported by runtime</span>}
                >
                    {(name) => <>{name()}</>}
                </Show>
                <Show when={w.image_digest}>
                    {(d) => <span class="text-muted"> @ {shortDigest(d())}</span>}
                </Show>
            </span>
        ),
    },
    {
        header: "Pods",
        align: "right",
        sortKey: "pod_count",
        sortType: "numeric",
        sortValue: (w) => w.pod_count,
        render: (w) => w.pod_count.toLocaleString(),
    },
    {
        header: "Match",
        sortKey: "match_state",
        sortValue: (w) => w.match_state,
        render: (w) => <MatchStatePill state={w.match_state} />,
    },
    {
        header: "Artifact",
        render: (w) => (
            <Show when={w.artifact_id} fallback={<span class="text-muted">—</span>}>
                {(id) => (
                    <span style={{ display: "flex", gap: "0.5rem" }}>
                        <A href={`/artifacts/${id()}`}>{w.artifact_name ?? "artifact"}</A>
                        <Show when={w.sbom_id}>
                            {(sbomID) => (
                                <A href={`/sboms/${sbomID()}`} class="text-muted">
                                    SBOM
                                </A>
                            )}
                        </Show>
                    </span>
                )}
            </Show>
        ),
    },
    {
        header: "Last seen",
        sortKey: "last_seen_at",
        sortValue: (w) => w.last_seen_at,
        render: (w) => (
            <span title={new Date(w.last_seen_at).toLocaleString()}>
                {relativeDate(w.last_seen_at)}
            </span>
        ),
    },
];

/**
 * WorkloadsTab lists every container the cluster reported, with the artifact
 * and SBOM behind it where one matched.
 */
export function WorkloadsTab(props: {
    rows: ClusterWorkload[] | undefined;
    loading: boolean;
    isError: boolean;
    error: unknown;
}) {
    return (
        <DataTable
            columns={workloadColumns}
            rows={props.rows}
            loading={props.loading}
            isError={props.isError}
            error={props.error}
            emptyTitle="No workloads reported"
            emptyMessage="No agent has pushed an inventory for this cluster yet. An empty inventory is not the same as a cluster running nothing."
        />
    );
}
