import "./ClusterDetail.css";
import { Show, createMemo } from "solid-js";
import { A, useParams } from "@solidjs/router";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import {
    Card,
    CardHeader,
    DetailGrid,
    DetailField,
    QueryBoundary,
    StatusPill,
} from "~/components/ui";
import { VulnSummaryBar } from "~/components/VulnBadge";
import { SkeletonHeader } from "~/components/Skeleton";
import { StalenessPill } from "./Clusters";
import { relativeDate, shortDigest, plural } from "~/utils/format";
import type { ClusterWorkload, WorkloadCoverage, WorkloadMatchState } from "~/api/client";
import { useCluster, useClusterWorkloads, useRunningVulnSummaries } from "~/api/queries";

/**
 * How each match state is presented. The label is the load-bearing part: hue
 * alone cannot carry "this is a gap, not a pass" (the same reasoning as
 * VulnBadge's lightness-not-hue scale), so every state says in words what it
 * is, and the two gap states say *which* gap so they stay distinguishable from
 * each other as well as from a match.
 */
const MATCH_PRESENTATION: Record<
    WorkloadMatchState,
    { label: string; variant: "success" | "warning" | "danger"; title: string }
> = {
    exact: {
        label: "matched",
        variant: "success",
        title: "The running digest matches an ingested SBOM exactly",
    },
    index: {
        label: "index match",
        variant: "warning",
        title:
            "The digest matches a multi-arch image index, so the SBOM is for the image as published — the exact platform running here is not known",
    },
    unknown: {
        label: "no SBOM",
        variant: "danger",
        title:
            "A real digest with no ingested SBOM: this image has never been scanned, so nothing below accounts for it",
    },
    unresolvable: {
        label: "no digest",
        variant: "danger",
        title:
            "No digest could be read from the container, so this image cannot be identified at all",
    },
};

export function MatchStatePill(props: { state: WorkloadMatchState }) {
    const p = () => MATCH_PRESENTATION[props.state];
    return (
        <StatusPill variant={p().variant} title={p().title}>
            {p().label}
        </StatusPill>
    );
}

/**
 * CoverageBand is the honest header for everything below it: how much of what
 * is running OCIDex can actually say something about.
 *
 * It comes before the vulnerability totals on purpose. A "0 known
 * vulnerabilities" figure computed over 3 of 40 running containers is not a
 * clean bill of health, and the only way a reader can tell is if the coverage
 * is stated first (ADR-044 K5).
 */
export function CoverageBand(props: { coverage: WorkloadCoverage }) {
    const pct = () =>
        props.coverage.total === 0
            ? "—"
            : `${Math.round((props.coverage.matched / props.coverage.total) * 100).toString()}%`;
    return (
        <div class="coverage-band">
            <div class="coverage-tile">
                <span class="coverage-tile-head">Containers</span>
                <span class="coverage-tile-value">{props.coverage.total.toLocaleString()}</span>
                <span class="coverage-tile-sub">running, deduplicated per image</span>
            </div>
            <div class="coverage-tile">
                <span class="coverage-tile-head">Matched</span>
                <span class="coverage-tile-value">{props.coverage.matched.toLocaleString()}</span>
                <span class="coverage-tile-sub">{pct()} of what is running</span>
            </div>
            <div class={props.coverage.unknown > 0 ? "coverage-tile bad" : "coverage-tile"}>
                <span class="coverage-tile-head">No SBOM</span>
                <span class="coverage-tile-value">{props.coverage.unknown.toLocaleString()}</span>
                <span class="coverage-tile-sub">never ingested — not assessed</span>
            </div>
            <div class={props.coverage.unresolvable > 0 ? "coverage-tile warn" : "coverage-tile"}>
                <span class="coverage-tile-head">Unresolvable</span>
                <span class="coverage-tile-value">
                    {props.coverage.unresolvable.toLocaleString()}
                </span>
                <span class="coverage-tile-sub">no digest readable — not assessed</span>
            </div>
        </div>
    );
}

/**
 * RunningVulns is the view the epic exists for: vulnerabilities scoped to the
 * images this cluster is actually running, rather than to the whole catalog.
 *
 * Totals are computed over *distinct* artifacts. The same image commonly runs as
 * a dozen workloads, and summing per workload would report a number a dozen
 * times too large — which is worse than no number, because it looks precise.
 */
export function RunningVulns(props: { workloads: ClusterWorkload[]; coverage: WorkloadCoverage }) {
    const artifactIDs = createMemo(() => [
        ...new Set(
            props.workloads
                .map((w) => w.artifact_id)
                .filter((id): id is string => id !== undefined && id !== ""),
        ),
    ]);
    // Wrapped rather than passed directly so the memo is read inside the hook's
    // own tracked scope: a new workload list has to refetch, not be ignored.
    const running = useRunningVulnSummaries(() => artifactIDs());
    const notAssessed = () => props.coverage.unknown + props.coverage.unresolvable;

    return (
        <Card style={{ "margin-bottom": "1rem" }}>
            <CardHeader
                title="Vulnerabilities in running images"
                count={artifactIDs().length}
                actions={
                    <A href="/vulnerabilities" class="dash-link">
                        Catalog-wide
                    </A>
                }
            />
            <Show
                when={artifactIDs().length > 0}
                fallback={
                    <p class="text-muted">
                        No running image matched an ingested SBOM, so there is nothing to report
                        here — and that is a coverage gap, not a clean result.
                    </p>
                }
            >
                <Show
                    when={!running().isPending}
                    fallback={<p class="text-muted">Loading vulnerability counts…</p>}
                >
                    <Show
                        when={!running().isError}
                        fallback={
                            <p class="text-muted">
                                Vulnerability counts could not be loaded for these images.
                            </p>
                        }
                    >
                        <Show
                            when={running().totals.total > 0}
                            fallback={
                                <p>
                                    No known vulnerabilities across the{" "}
                                    {plural(artifactIDs().length, "matched image")} running here.
                                </p>
                            }
                        >
                            <VulnSummaryBar summary={running().totals} />
                            <p class="text-muted" style={{ "margin-top": "0.5rem" }}>
                                Across {plural(artifactIDs().length, "distinct image")} running in
                                this cluster.
                            </p>
                        </Show>
                    </Show>
                </Show>
            </Show>
            <Show when={notAssessed() > 0}>
                <span class="coverage-caveat">
                    {plural(notAssessed(), "running container")} above are excluded from these
                    counts: {props.coverage.unknown.toLocaleString()} have no ingested SBOM and{" "}
                    {props.coverage.unresolvable.toLocaleString()} have no readable digest. Their
                    exposure is unknown, not zero.
                </span>
            </Show>
        </Card>
    );
}

/**
 * ClusterDetail shows one cluster's running inventory: the coverage rollup, the
 * vulnerabilities of the images it actually runs, and every container with its
 * match state and a link through to the artifact and SBOM behind it.
 */
export default function ClusterDetail() {
    const params = useParams<{ id: string }>();
    const clusterQuery = useCluster(() => params.id);
    const workloadsQuery = useClusterWorkloads(() => params.id);

    const columns: Column<ClusterWorkload>[] = [
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
                    {w.image_ref}
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
                <Show
                    when={w.artifact_id}
                    fallback={<span class="text-muted">—</span>}
                >
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

    return (
        <>
            <QueryBoundary query={clusterQuery} loading={<SkeletonHeader />}>
                {(cluster) => (
                    <div class="page-header">
                        <div class="page-header-row">
                            <div>
                                <h2>{cluster().name}</h2>
                                <p>{cluster().description ?? "Kubernetes cluster inventory"}</p>
                            </div>
                        </div>
                        <DetailGrid>
                            <DetailField label="Namespace" when={cluster().namespace_name}>
                                {cluster().namespace_name}
                            </DetailField>
                            <DetailField label="Last reported">
                                <StalenessPill lastSeenAt={cluster().last_seen_at} />
                            </DetailField>
                            <DetailField label="Cluster ID" valueClass="font-mono text-sm">
                                {cluster().id}
                            </DetailField>
                        </DetailGrid>
                    </div>
                )}
            </QueryBoundary>

            <Show when={workloadsQuery.data}>
                {(data) => (
                    <>
                        <CoverageBand coverage={data().coverage} />
                        <RunningVulns workloads={data().data} coverage={data().coverage} />
                    </>
                )}
            </Show>

            <DataTable
                columns={columns}
                rows={workloadsQuery.data?.data}
                loading={workloadsQuery.isLoading}
                isError={workloadsQuery.isError}
                error={workloadsQuery.error}
                emptyTitle="No workloads reported"
                emptyMessage="No agent has pushed an inventory for this cluster yet. An empty inventory is not the same as a cluster running nothing."
            />
        </>
    );
}
