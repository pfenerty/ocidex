import { Show, For } from "solid-js";
import { A } from "@solidjs/router";
import DataTable from "~/components/DataTable";
import type { Column, SortDir } from "~/components/DataTable";
import { VulnCountBadges } from "~/components/VulnBadge";
import { relativeDate, shortDigest } from "~/utils/format";
import { imageRefName } from "~/utils/oci";
import type { ClusterWorkload, NamespaceFacet, PaginationMeta, WorkloadMatchState } from "~/api/client";
import type { WorkloadSortKey } from "~/api/queries";
import { MATCH_PRESENTATION, MatchStatePill } from "./matchState";

/**
 * WorkloadVulnCell renders the findings in a workload's matched SBOM.
 *
 * The three outcomes are rendered as three different things on purpose. An
 * image nobody has assessed and an image assessed with nothing wrong are
 * different facts, and this is the cell where they are most easily confused —
 * VulnCountBadges renders all-zero as an em dash, which is exactly what an
 * absent count would look like too (ADR-044 K5).
 */
function WorkloadVulnCell(props: { workload: ClusterWorkload }) {
    const vulns = () => props.workload.vulns;
    const total = () => {
        const v = vulns();
        return v === undefined ? 0 : v.critical + v.high + v.medium + v.low;
    };
    return (
        <Show
            when={vulns()}
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
        header: "Vulnerabilities",
        sortKey: "vuln_count",
        sortType: "numeric",
        sortValue: (w) => {
            const v = w.vulns;
            return v === undefined ? -1 : v.critical * 1_000_000 + v.high * 1_000 + v.medium;
        },
        render: (w) => <WorkloadVulnCell workload={w} />,
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

const MATCH_STATE_OPTIONS: WorkloadMatchState[] = ["exact", "index", "unknown", "unresolvable"];

export interface WorkloadFilters {
    q: string;
    k8sNamespace: string;
    matchState: string;
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
        </div>
    );
}

/**
 * WorkloadsTab lists every container the cluster reported, with the artifact,
 * SBOM and findings behind it where one matched.
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
            emptyTitle="No workloads reported"
            emptyMessage="No agent has pushed an inventory for this cluster yet. An empty inventory is not the same as a cluster running nothing."
        />
    );
}
