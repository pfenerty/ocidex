import "./ClusterDetail.css";
import { Show, createSignal } from "solid-js";
import { useParams, useSearchParams } from "@solidjs/router";
import {
    DetailGrid,
    DetailField,
    QueryBoundary,
    TabBar,
    type TabDef,
} from "~/components/ui";
import { SkeletonHeader } from "~/components/Skeleton";
import { StalenessPill } from "../Clusters";
import { useCluster, useClusterNamespaces, useClusterWorkloads } from "~/api/queries";
import type { WorkloadSortKey } from "~/api/queries";
import type { SortDir } from "~/components/DataTable";
import type { WorkloadMatchState } from "~/api/client";
import { CoverageBand } from "./CoverageBand";
import { OverviewTab } from "./OverviewTab";
import { WorkloadsTab, WorkloadsFilterBar } from "./WorkloadsTab";
import { VulnerabilitiesTab } from "./VulnerabilitiesTab";
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
                            <OverviewTab clusterId={params.id} coverage={data().coverage} />
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
                            <VulnerabilitiesTab
                                clusterId={params.id}
                                coverage={data().coverage}
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

/** The sort keys the API accepts, so a hand-edited URL cannot request one it doesn't. */
const SORT_KEYS: WorkloadSortKey[] = [
    "k8s_namespace",
    "workload_name",
    "container_name",
    "image_ref",
    "match_state",
    "pod_count",
    "last_seen_at",
    "vuln_count",
];

/**
 * WorkloadsTabPanel owns the workload filters, sort and page offset, all of
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
    const sortBy = (): WorkloadSortKey => {
        const raw = one(props.searchParams.sort);
        return SORT_KEYS.find((candidate) => candidate === raw) ?? "k8s_namespace";
    };
    const sortDir = (): SortDir => (one(props.searchParams.dir) === "desc" ? "desc" : "asc");
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

    const namespacesQuery = useClusterNamespaces(() => props.clusterId);
    const query = useClusterWorkloads(
        () => props.clusterId,
        () => ({
            match_state: props.matchState,
            ...(k8sNamespace() === "" ? {} : { k8s_namespace: k8sNamespace() }),
            ...(q() === "" ? {} : { q: q() }),
            sort: sortBy(),
            dir: sortDir(),
            limit: 50,
            offset: offset(),
        }),
    );

    return (
        <>
            <WorkloadsFilterBar
                filters={{ q: draftQuery(), k8sNamespace: k8sNamespace(), matchState: props.matchState ?? "" }}
                namespaces={namespacesQuery.data?.data}
                onQueryInput={onQueryInput}
                // Every filter change resets the offset: page 4 of the old
                // result set is a meaningless place to land in the new one.
                onNamespaceChange={(value) =>
                    props.setSearchParams({ k8s_namespace: value, offset: undefined })
                }
                onMatchStateChange={(value) =>
                    props.setSearchParams({ match_state: value, offset: undefined })
                }
            />
            <WorkloadsTab
                rows={query.data?.data}
                loading={query.isFetching}
                isError={query.isError}
                error={query.error}
                sortBy={sortBy()}
                sortDir={sortDir()}
                onSort={(key, dir) => props.setSearchParams({ sort: key, dir, offset: undefined })}
                pagination={query.data?.pagination}
                onPageChange={(next) => props.setSearchParams({ offset: next === 0 ? undefined : next })}
            />
        </>
    );
}
