import { Show, For } from "solid-js";
import { A } from "@solidjs/router";
import DataTable from "~/components/DataTable";
import type { Column, SortDir } from "~/components/DataTable";
import { VulnCountBadges } from "~/components/VulnBadge";
import { relativeDate, shortDigest } from "~/utils/format";
import { splitImageRef } from "~/utils/oci";
import type {
    ClusterImage,
    ClusterWorkload,
    NamespaceFacet,
    PaginationMeta,
    WorkloadMatchState,
} from "~/api/client";
import type { ImageSortKey, WorkloadSortKey } from "~/api/queries";
import { MATCH_PRESENTATION, MatchStatePill } from "./matchState";

/** The two ways this tab can group the same rows. */
export type InventoryGrouping = "image" | "workload";

type VulnCounts = ClusterWorkload["vulns"];

/**
 * InventoryVulnCell renders the findings in an image's matched SBOM.
 *
 * The three outcomes are rendered as three different things on purpose. An
 * image nobody has assessed and an image assessed with nothing wrong are
 * different facts, and this is the cell where they are most easily confused —
 * VulnCountBadges renders all-zero as an em dash, which is exactly what an
 * absent count would look like too (ADR-044 K5).
 *
 * Both groupings share this cell rather than each rendering their own, so the
 * guard cannot hold in one view and lapse in the other.
 */
export function InventoryVulnCell(props: { vulns: VulnCounts }) {
    const total = () => {
        const v = props.vulns;
        return v === undefined ? 0 : v.critical + v.high + v.medium + v.low;
    };
    return (
        <Show
            when={props.vulns}
            fallback={
                <span class="text-muted italic" title="No SBOM matched this image, so it has never been assessed">
                    not assessed
                </span>
            }
        >
            {(v) => (
                <Show when={total() > 0} fallback={<span class="text-muted">no findings</span>}>
                    <VulnCountBadges
                        criticalCount={v().critical}
                        highCount={v().high}
                        mediumCount={v().medium}
                        lowCount={v().low}
                    />
                </Show>
            )}
        </Show>
    );
}

/** Sorts an unassessed image last: absent counts are not a score of zero. */
function vulnSortValue(vulns: VulnCounts): number {
    return vulns === undefined ? -1 : vulns.critical * 1_000_000 + vulns.high * 1_000 + vulns.medium;
}

interface ImageIdentity {
    image_ref: string;
    image_digest?: string;
    artifact_id?: string;
    artifact_name?: string;
    sbom_id?: string;
}

/**
 * ImageCell renders the image reference and, beneath it, what OCIDex knows the
 * image to be.
 *
 * The reference is rendered whole, with everything before the last path segment
 * muted: a 60-character ref is mostly registry and org, and truncating it would
 * hide the host — the one part of the ref the Gaps tab needs a reader to see.
 */
export function ImageCell(props: { row: ImageIdentity }) {
    const parts = () => splitImageRef(props.row.image_ref);
    return (
        <div class="inventory-cell">
            <span class="font-mono text-sm" title={props.row.image_digest ?? props.row.image_ref}>
                <Show
                    when={parts()}
                    fallback={<span class="text-muted italic">name not reported by runtime</span>}
                >
                    {(p) => (
                        <>
                            <span class="text-muted">{p().prefix}</span>
                            {p().name}
                        </>
                    )}
                </Show>
                <Show when={props.row.image_digest}>
                    {(d) => <span class="text-muted"> @ {shortDigest(d())}</span>}
                </Show>
            </span>
            <Show when={props.row.artifact_id}>
                {(id) => (
                    <span class="inventory-cell-sub">
                        <A href={`/artifacts/${id()}`}>{props.row.artifact_name ?? "artifact"}</A>
                        <Show when={props.row.sbom_id}>
                            {(sbomID) => (
                                <A href={`/sboms/${sbomID()}`} class="text-muted">
                                    SBOM
                                </A>
                            )}
                        </Show>
                    </span>
                )}
            </Show>
        </div>
    );
}

/**
 * The by-workload columns: one row per container the cluster reported.
 *
 * "Last seen" is a title rather than a column — on a healthy cluster every row
 * reads "just now", so it spent a column's width to say nothing. The artifact
 * and SBOM links moved under the image they describe, which is what took this
 * table off the horizontal scrollbar it used to need.
 */
export const workloadColumns: Column<ClusterWorkload>[] = [
    {
        header: "Workload",
        sortKey: "workload_name",
        sortValue: (w) => w.workload_name,
        render: (w) => (
            <div class="inventory-cell" title={`Last seen ${new Date(w.last_seen_at).toLocaleString()}`}>
                <span>
                    <span class="text-muted">{w.k8s_namespace}/</span>
                    {w.workload_name}
                </span>
                <span class="inventory-cell-sub text-muted">
                    {w.workload_kind} · {w.container_name} · seen {relativeDate(w.last_seen_at)}
                </span>
            </div>
        ),
    },
    {
        header: "Image",
        sortKey: "image_ref",
        sortValue: (w) => w.image_ref,
        render: (w) => <ImageCell row={w} />,
    },
    {
        header: "Match",
        sortKey: "match_state",
        sortValue: (w) => w.match_state,
        render: (w) => <MatchStatePill state={w.match_state} />,
    },
    {
        header: "Vulnerabilities",
        sortKey: "vuln_count",
        sortType: "numeric",
        sortValue: (w) => vulnSortValue(w.vulns),
        render: (w) => <InventoryVulnCell vulns={w.vulns} />,
    },
    {
        header: "Pods",
        align: "right",
        sortKey: "pod_count",
        sortType: "numeric",
        sortValue: (w) => w.pod_count,
        render: (w) => w.pod_count.toLocaleString(),
    },
];

/**
 * The by-image columns: one row per distinct image, with the workloads running
 * it collapsed into counts.
 *
 * Match and vulnerabilities render exactly as they do by workload — same cells,
 * same K5 guard — because they are properties of the image in both views. What
 * the grouping adds is the two counts that say how much of the cluster one
 * ingest would cover.
 */
export const imageColumns: Column<ClusterImage>[] = [
    {
        header: "Image",
        sortKey: "image_ref",
        sortValue: (i) => i.image_ref,
        render: (i) => <ImageCell row={i} />,
    },
    {
        header: "Match",
        sortKey: "match_state",
        sortValue: (i) => i.match_state,
        render: (i) => <MatchStatePill state={i.match_state} />,
    },
    {
        header: "Vulnerabilities",
        sortKey: "vuln_count",
        sortType: "numeric",
        sortValue: (i) => vulnSortValue(i.vulns),
        render: (i) => <InventoryVulnCell vulns={i.vulns} />,
    },
    {
        header: "Workloads",
        align: "right",
        sortKey: "workload_count",
        sortType: "numeric",
        sortValue: (i) => i.workload_count,
        render: (i) => (
            <div class="inventory-cell inventory-cell-right">
                <span>{i.workload_count.toLocaleString()}</span>
                <Show when={i.sample_workload}>
                    {(sample) => (
                        <span
                            class="inventory-cell-sub text-muted"
                            title={`Runs in ${i.namespace_count.toLocaleString()} Kubernetes namespace${i.namespace_count === 1 ? "" : "s"}`}
                        >
                            {i.sample_namespace ?? ""}/{sample()}
                            <Show when={i.workload_count > 1}>
                                {" "}
                                +{(i.workload_count - 1).toLocaleString()}
                            </Show>
                        </span>
                    )}
                </Show>
            </div>
        ),
    },
    {
        header: "Pods",
        align: "right",
        sortKey: "pod_count",
        sortType: "numeric",
        sortValue: (i) => i.pod_count,
        render: (i) => i.pod_count.toLocaleString(),
    },
];

const MATCH_STATE_OPTIONS: WorkloadMatchState[] = ["exact", "index", "unknown", "unresolvable"];

export interface WorkloadFilters {
    q: string;
    k8sNamespace: string;
    matchState: string;
    group: InventoryGrouping;
}

/**
 * WorkloadsFilterBar is the standard search-bar row (see Artifacts.tsx): a
 * debounced text box plus selects, all writing straight to search params so a
 * narrowed view is a URL someone can paste into an issue.
 *
 * The namespace options come from the facet query rather than the rows on
 * screen — the list is paginated, so options derived from the current page
 * would silently omit most of the cluster.
 */
export function WorkloadsFilterBar(props: {
    filters: WorkloadFilters;
    namespaces: NamespaceFacet[] | undefined;
    onQueryInput: (value: string) => void;
    onNamespaceChange: (value: string | undefined) => void;
    onMatchStateChange: (value: string | undefined) => void;
    onGroupChange: (value: InventoryGrouping) => void;
}) {
    return (
        <div class="search-bar mb-4">
            <input
                type="text"
                placeholder="Filter by workload, container or image…"
                value={props.filters.q}
                onInput={(e) => props.onQueryInput(e.currentTarget.value)}
            />
            <select
                value={props.filters.k8sNamespace}
                onChange={(e) =>
                    props.onNamespaceChange(
                        e.currentTarget.value === "" ? undefined : e.currentTarget.value,
                    )
                }
            >
                <option value="">All namespaces</option>
                <For each={props.namespaces ?? []}>
                    {(ns) => (
                        <option value={ns.k8s_namespace}>
                            {ns.k8s_namespace} ({ns.workload_count.toLocaleString()})
                        </option>
                    )}
                </For>
            </select>
            <select
                value={props.filters.matchState}
                onChange={(e) =>
                    props.onMatchStateChange(
                        e.currentTarget.value === "" ? undefined : e.currentTarget.value,
                    )
                }
            >
                <option value="">All match states</option>
                <For each={MATCH_STATE_OPTIONS}>
                    {(state) => (
                        <option value={state} title={MATCH_PRESENTATION[state].title}>
                            {MATCH_PRESENTATION[state].label}
                        </option>
                    )}
                </For>
            </select>
            <select
                aria-label="Grouping"
                data-testid="grouping-select"
                value={props.filters.group}
                onChange={(e) =>
                    props.onGroupChange(e.currentTarget.value === "workload" ? "workload" : "image")
                }
            >
                <option value="image" title="One row per distinct image — the unit an ingest fixes">
                    One row per image
                </option>
                <option value="workload" title="One row per container the cluster reported">
                    One row per workload
                </option>
            </select>
        </div>
    );
}

const EMPTY_TITLE = "No workloads reported";
const EMPTY_MESSAGE =
    "No agent has pushed an inventory for this cluster yet. An empty inventory is not the same as a cluster running nothing.";

/**
 * WorkloadsTab lists the cluster's running inventory, grouped either way.
 *
 * Sort and paging are both server-side: the list is offset-paginated, so
 * reordering only the rows that happen to be on the current page would
 * misrepresent the cluster.
 */
export function WorkloadsTab(props: {
    rows: ClusterWorkload[] | undefined;
    loading: boolean;
    isError: boolean;
    error: unknown;
    sortBy: WorkloadSortKey;
    sortDir: SortDir;
    onSort: (sortKey: string, dir: SortDir) => void;
    pagination: PaginationMeta | undefined;
    onPageChange: (offset: number) => void;
}) {
    return (
        <DataTable
            columns={workloadColumns}
            rows={props.rows}
            loading={props.loading}
            isError={props.isError}
            error={props.error}
            sortBy={props.sortBy}
            sortDir={props.sortDir}
            onSort={props.onSort}
            pagination={
                props.pagination
                    ? { pagination: props.pagination, onPageChange: props.onPageChange }
                    : undefined
            }
            emptyTitle={EMPTY_TITLE}
            emptyMessage={EMPTY_MESSAGE}
        />
    );
}

/** ImagesTab is WorkloadsTab's other grouping; see imageColumns. */
export function ImagesTab(props: {
    rows: ClusterImage[] | undefined;
    loading: boolean;
    isError: boolean;
    error: unknown;
    sortBy: ImageSortKey;
    sortDir: SortDir;
    onSort: (sortKey: string, dir: SortDir) => void;
    pagination: PaginationMeta | undefined;
    onPageChange: (offset: number) => void;
}) {
    return (
        <DataTable
            columns={imageColumns}
            rows={props.rows}
            loading={props.loading}
            isError={props.isError}
            error={props.error}
            sortBy={props.sortBy}
            sortDir={props.sortDir}
            onSort={props.onSort}
            pagination={
                props.pagination
                    ? { pagination: props.pagination, onPageChange: props.onPageChange }
                    : undefined
            }
            emptyTitle={EMPTY_TITLE}
            emptyMessage={EMPTY_MESSAGE}
        />
    );
}
