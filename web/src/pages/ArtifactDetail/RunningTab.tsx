import { Show } from "solid-js";
import { A } from "@solidjs/router";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { StatusPill } from "~/components/ui";
import type { components } from "~/types/openapi";

export type RunningWorkload = components["schemas"]["RunningWorkloadResponse"];

/** The cluster names a set of workloads runs in, sorted and distinct. */
export function clusterNames(rows: RunningWorkload[]): string[] {
    return [...new Set(rows.map((r) => r.clusterName))].sort();
}

/**
 * Which rows run a given version: by SBOM, or by version key, since one
 * version can have an SBOM per platform and a workload names only the one its
 * digest matched.
 */
export function runningForVersion(rows: RunningWorkload[], sbomId: string, versionKey: string): RunningWorkload[] {
    return rows.filter((r) => r.sbomId === sbomId || (r.subjectVersion !== undefined && r.subjectVersion === versionKey));
}

const columns: Column<RunningWorkload>[] = [
    {
        header: "Cluster",
        sortValue: (r) => r.clusterName,
        render: (r) => <A href={`/clusters/${r.clusterId}?tab=workloads&q=${encodeURIComponent(r.workloadName)}`}>{r.clusterName}</A>,
    },
    {
        header: "Workload",
        class: "col-ref",
        sortValue: (r) => `${r.k8sNamespace}/${r.workloadName}`,
        render: (r) => (
            <>
                <span class="text-muted">{r.k8sNamespace}/</span>
                {r.workloadName}
                <span class="text-muted text-sm"> · {r.containerName}</span>
            </>
        ),
    },
    {
        header: "Version",
        sortValue: (r) => r.subjectVersion ?? "",
        render: (r) => (
            <Show when={r.sbomId} fallback={<span class="text-muted">—</span>}>
                {(id) => <A href={`/sboms/${id()}`}>{r.subjectVersion ?? "SBOM"}</A>}
            </Show>
        ),
    },
    {
        header: "Match",
        render: (r) => (
            <StatusPill
                variant={r.matchState === "exact" ? "success" : "primary"}
                title={r.matchState === "index" ? "Matched by index digest: which platform is running is unknown" : undefined}
            >
                {r.matchState === "exact" ? "exact" : "index"}
            </StatusPill>
        ),
    },
    { header: "Pods", align: "right", sortValue: (r) => r.podCount, render: (r) => r.podCount.toLocaleString() },
];

/**
 * RunningTab answers "is this deployed, and where" for an artifact
 * (ocidex-70eo.8): every visible workload running any of its versions.
 */
export function RunningTab(props: {
    rows: RunningWorkload[] | undefined;
    loading: boolean;
    isError: boolean;
    error: Error | null;
}) {
    return (
        <DataTable
            columns={columns}
            rows={props.rows}
            loading={props.loading}
            isError={props.isError}
            error={props.error}
            emptyTitle="Not running in any cluster you can see"
            emptyMessage="Connect a cluster to see where images run; only clusters whose namespace you can see are counted."
        />
    );
}
