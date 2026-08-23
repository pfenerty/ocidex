import "./ClusterDetail.css";
import { Show, createSignal } from "solid-js";
import { useParams, useSearchParams } from "@solidjs/router";
import { DetailField, DetailGrid, PageHeader, QueryBoundary, TabBar, type TabDef } from "~/components/ui";
import { SkeletonHeader } from "~/components/Skeleton";
import { StalenessPill } from "../Clusters";
import {
    useCluster,
    useClusterImages,
    useClusterNamespaces,
    useClusterWorkloads,
} from "~/api/queries";
import type {
    WorkloadSortKey,
    ImageSortKey,
    ClusterVulnSortKey,
    VulnSeverityFilter,
} from "~/api/queries";
import type { SortDir } from "~/components/DataTable";
import type { WorkloadMatchState } from "~/api/client";
import { CoverageBand } from "./CoverageBand";
import { OverviewTab } from "./OverviewTab";
import { WorkloadsTab, ImagesTab, WorkloadsFilterBar } from "./WorkloadsTab";
import type { InventoryGrouping } from "./WorkloadsTab";
import { VulnerabilitiesTab, SEVERITIES, SORT_KEYS as VULN_SORT_KEYS } from "./VulnerabilitiesTab";
import { GapsTab } from "./GapsTab";

const TABS = ["overview", "workloads", "vulnerabilities", "gaps"] as const;
type Tab = (typeof TABS)[number];

const tabs: TabDef<Tab>[] = [
    { id: "overview", label: "Overview" },
    { id: "workloads", label: "Workloads" },
    { id: "vulnerabilities", label: "Vulnerabilities", title: "Vulnerabilities in the images this cluster runs" },
    { id: "gaps", label: "Gaps", title: "Containers OCIDex cannot assess, and why" },
];

const MATCH_STATES: WorkloadMatchState[] = ["exact", "index", "unknown", "unresolvable"];

/** Search params arrive as string | string[]; take the first value either way. */
function one(v: string | string[] | undefined): string | undefined {
    return Array.isArray(v) ? v[0] : v;
}

/**
 * ClusterDetail shows one cluster's running inventory across four tabs, under a
 * coverage band that qualifies all of them.
 *
 * The active tab lives in a search param rather than component state so a view
 * is linkable — "the 12 containers with no SBOM in prod" is a URL someone can
 * paste into an issue, which is most of what makes this page actionable.
 */
export default function ClusterDetail() {
    const params = useParams<{ id: string }>();
    const [searchParams, setSearchParams] = useSearchParams();
    const clusterQuery = useCluster(() => params.id);

    const tab = (): Tab => {
        const t = one(searchParams.tab);
        return TABS.find((candidate) => candidate === t) ?? "overview";
    };
    // A hand-edited URL can say anything; an unrecognised state is dropped
    // rather than forwarded, so the table shows everything instead of nothing.
    const matchState = (): WorkloadMatchState | undefined => {
        const raw = one(searchParams.match_state);
        return MATCH_STATES.find((candidate) => candidate === raw);
    };

    // The band's counts come from the unfiltered workload query, so they stay
    // cluster-wide however a tab below has narrowed its own view (ADR-044 K5).
    const coverageQuery = useClusterWorkloads(() => params.id, () => ({ limit: 1 }));

    return (
        <>
            <QueryBoundary query={clusterQuery} loading={<SkeletonHeader />}>
                {(cluster) => (
                    <PageHeader
                        title={cluster().name}
                        subtitle={cluster().description ?? "Kubernetes cluster inventory"}
                        footer={
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
                        }
                    />
                )}
            </QueryBoundary>

            <Show when={coverageQuery.data}>
                {(data) => (
                    <CoverageBand
                        coverage={data().coverage}
                        clusterId={params.id}
                        active={tab()}
                        activeMatchState={matchState()}
                    />
                )}
            </Show>

            <TabBar
                tabs={tabs}
                active={tab()}
                onSelect={(id) => {
                    // Filters belong to the tab that owns them; carrying a
                    // match_state onto the vulnerability list would silently
                    // apply to nothing.
                    setSearchParams({
                        tab: id,
                        match_state: undefined,
                        k8s_namespace: undefined,
                        q: undefined,
                        severity: undefined,
                        sort: undefined,
                        dir: undefined,
                        offset: undefined,
                    });
                }}
            />

            <Show when={coverageQuery.data} fallback={<SkeletonHeader />}>
                {(data) => (
                    <>
                        <Show when={tab() === "overview"}>
                            <OverviewTab
                                clusterId={params.id}
                                clusterName={clusterQuery.data?.name ?? "This cluster"}
                                coverage={data().coverage}
                                // Undefined while the cluster loads, which is
                                // also the never-reported value — so the
                                // first-run panel is what shows until the
                                // timestamp says otherwise, rather than a
                                // zeroed summary that would read as clean.
                                lastSeenAt={clusterQuery.data?.last_seen_at}
                                // Defaults to on server-side; treated as off
                                // only while the cluster is still loading, so
                                // the line never claims ingest is running
                                // before it knows.
                                autoIngest={clusterQuery.data?.auto_ingest ?? false}
                            />
                        </Show>
                        <Show when={tab() === "workloads"}>
                            <WorkloadsTabPanel
                                clusterId={params.id}
                                matchState={matchState()}
                                searchParams={searchParams}
                                setSearchParams={setSearchParams}
                            />
                        </Show>
                        <Show when={tab() === "vulnerabilities"}>
                            <VulnerabilitiesTabPanel
                                clusterId={params.id}
                                coverage={data().coverage}
                                searchParams={searchParams}
                                setSearchParams={setSearchParams}
                            />
                        </Show>
                        <Show when={tab() === "gaps"}>
                            <GapsTab clusterId={params.id} coverage={data().coverage} />
                        </Show>
                    </>
                )}
            </Show>
        </>
    );
}

/**
 * The sort keys the API accepts for each grouping, so a hand-edited URL cannot
 * request one it doesn't — and so switching grouping cannot carry over a key
 * the other list has no column for.
 */
const SORT_KEYS: Record<InventoryGrouping, string[]> = {
    workload: [
        "k8s_namespace",
        "workload_name",
        "container_name",
        "image_ref",
        "match_state",
        "pod_count",
        "last_seen_at",
        "vuln_count",
    ],
    image: ["image_ref", "match_state", "workload_count", "pod_count", "last_seen_at", "vuln_count"],
};

/**
 * Worst findings first, in both groupings.
 *
 * The old default was namespace ascending, which is alphabetical rather than
 * actionable: it opened on whatever happens to be called "argocd". The first
 * screen should be the one worth acting on.
 */
const DEFAULT_SORT = "vuln_count";

/**
 * WorkloadsTabPanel owns the grouping, filters, sort and page offset, all of
 * which live in search params so a narrowed view is linkable.
 *
 * The text box is the one exception: it is debounced through a local signal so
 * typing does not push a history entry per keystroke, and the search param
 * catches up 300ms later.
 */
function WorkloadsTabPanel(props: {
    clusterId: string;
    matchState: WorkloadMatchState | undefined;
    searchParams: Record<string, string | string[] | undefined>;
    setSearchParams: (params: Record<string, string | number | undefined>) => void;
}) {
    const q = () => one(props.searchParams.q) ?? "";
    const k8sNamespace = () => one(props.searchParams.k8s_namespace) ?? "";
    // By image is the default because an image is the unit of the remedy: a
    // rollout of one unscanned image across fourteen deployments is one SBOM to
    // ingest, and fourteen near-identical rows to read.
    const group = (): InventoryGrouping =>
        one(props.searchParams.group) === "workload" ? "workload" : "image";
    const sortBy = (): string => {
        const raw = one(props.searchParams.sort);
        return SORT_KEYS[group()].find((candidate) => candidate === raw) ?? DEFAULT_SORT;
    };
    // Severity's useful default is worst-first, the opposite of the ascending
    // default every text column wants.
    const sortDir = (): SortDir => {
        const raw = one(props.searchParams.dir);
        if (raw === "asc" || raw === "desc") return raw;
        return sortBy() === DEFAULT_SORT ? "desc" : "asc";
    };
    const offset = () => {
        const parsed = Number(one(props.searchParams.offset));
        return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
    };

    // Mirrors q() so the input stays responsive while the debounce runs; the
    // search param remains the source of truth for the query itself.
    const [draftQuery, setDraftQuery] = createSignal(q());
    let debounce: ReturnType<typeof setTimeout> | undefined;
    const onQueryInput = (value: string) => {
        setDraftQuery(value);
        clearTimeout(debounce);
        debounce = setTimeout(() => {
            props.setSearchParams({ q: value === "" ? undefined : value, offset: undefined });
        }, 300);
    };

    // The filters are shared, so the two hooks take the same params; only the
    // cluster id is withheld from the inactive one, which is what its `enabled`
    // gate reads. Both hooks must still be called on every render.
    const listParams = () => ({
        match_state: props.matchState,
        ...(k8sNamespace() === "" ? {} : { k8s_namespace: k8sNamespace() }),
        ...(q() === "" ? {} : { q: q() }),
        dir: sortDir(),
        limit: 50,
        offset: offset(),
    });
    const workloadId = () => (group() === "workload" ? props.clusterId : undefined);
    const imageId = () => (group() === "image" ? props.clusterId : undefined);

    const namespacesQuery = useClusterNamespaces(() => props.clusterId);
    const workloadQuery = useClusterWorkloads(workloadId, () => ({
        ...listParams(),
        sort: sortBy() as WorkloadSortKey,
    }));
    const imageQuery = useClusterImages(imageId, () => ({
        ...listParams(),
        sort: sortBy() as ImageSortKey,
    }));

    // Every filter change resets the offset: page 4 of the old result set is a
    // meaningless place to land in the new one. Changing the grouping drops the
    // sort too — the key it was on may not exist in the other list.
    const onSort = (key: string, dir: SortDir) =>
        props.setSearchParams({ sort: key, dir, offset: undefined });
    const onPageChange = (next: number) =>
        props.setSearchParams({ offset: next === 0 ? undefined : next });

    return (
        <>
            <WorkloadsFilterBar
                filters={{
                    q: draftQuery(),
                    k8sNamespace: k8sNamespace(),
                    matchState: props.matchState ?? "",
                    group: group(),
                }}
                namespaces={namespacesQuery.data?.data}
                onQueryInput={onQueryInput}
                onNamespaceChange={(value) =>
                    props.setSearchParams({ k8s_namespace: value, offset: undefined })
                }
                onMatchStateChange={(value) =>
                    props.setSearchParams({ match_state: value, offset: undefined })
                }
                onGroupChange={(value) =>
                    props.setSearchParams({
                        group: value === "image" ? undefined : value,
                        sort: undefined,
                        dir: undefined,
                        offset: undefined,
                    })
                }
            />
            <Show
                when={group() === "image"}
                fallback={
                    <WorkloadsTab
                        rows={workloadQuery.data?.data}
                        loading={workloadQuery.isFetching}
                        isError={workloadQuery.isError}
                        error={workloadQuery.error}
                        sortBy={sortBy() as WorkloadSortKey}
                        sortDir={sortDir()}
                        onSort={onSort}
                        pagination={workloadQuery.data?.pagination}
                        onPageChange={onPageChange}
                    />
                }
            >
                <ImagesTab
                    rows={imageQuery.data?.data}
                    loading={imageQuery.isFetching}
                    isError={imageQuery.isError}
                    error={imageQuery.error}
                    sortBy={sortBy() as ImageSortKey}
                    sortDir={sortDir()}
                    onSort={onSort}
                    pagination={imageQuery.data?.pagination}
                    onPageChange={onPageChange}
                />
            </Show>
        </>
    );
}

/**
 * VulnerabilitiesTabPanel keeps the severity filter, sort and offset in search
 * params, for the same reason the workload panel does: a narrowed view of what
 * a cluster is running is the thing people want to send each other.
 */
function VulnerabilitiesTabPanel(props: {
    clusterId: string;
    coverage: { total: number; matched: number; unknown: number; unresolvable: number; pods: number };
    searchParams: Record<string, string | string[] | undefined>;
    setSearchParams: (params: Record<string, string | number | undefined>) => void;
}) {
    const severity = (): VulnSeverityFilter | undefined => {
        const raw = one(props.searchParams.severity);
        return SEVERITIES.find((candidate) => candidate === raw);
    };
    const sortBy = (): ClusterVulnSortKey => {
        const raw = one(props.searchParams.sort);
        return VULN_SORT_KEYS.find((candidate) => candidate === raw) ?? "severity";
    };
    // Severity's useful default is worst-first, which is the opposite of the
    // ascending default every other column wants.
    const sortDir = (): SortDir => {
        const raw = one(props.searchParams.dir);
        if (raw === "asc" || raw === "desc") return raw;
        return sortBy() === "canonical_id" ? "asc" : "desc";
    };
    const offset = () => {
        const parsed = Number(one(props.searchParams.offset));
        return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
    };

    return (
        <VulnerabilitiesTab
            clusterId={props.clusterId}
            coverage={props.coverage}
            severity={severity()}
            sortBy={sortBy()}
            sortDir={sortDir()}
            offset={offset()}
            onSeverityChange={(value) =>
                props.setSearchParams({ severity: value, offset: undefined })
            }
            onSort={(key, dir) => props.setSearchParams({ sort: key, dir, offset: undefined })}
            onPageChange={(next) =>
                props.setSearchParams({ offset: next === 0 ? undefined : next })
            }
        />
    );
}
