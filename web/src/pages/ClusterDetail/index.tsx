import "./ClusterDetail.css";
import { Show } from "solid-js";
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
import { useCluster, useClusterWorkloads } from "~/api/queries";
import type { WorkloadMatchState } from "~/api/client";
import { CoverageBand } from "./CoverageBand";
import { OverviewTab } from "./OverviewTab";
import { WorkloadsTab } from "./WorkloadsTab";
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
                    setSearchParams({ tab: id, match_state: undefined });
                }}
            />

            <Show when={coverageQuery.data} fallback={<SkeletonHeader />}>
                {(data) => (
                    <>
                        <Show when={tab() === "overview"}>
                            <OverviewTab clusterId={params.id} coverage={data().coverage} />
                        </Show>
                        <Show when={tab() === "workloads"}>
                            <WorkloadsTabPanel clusterId={params.id} matchState={matchState()} />
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

/** Fetches the workload page for the current filters and renders the table. */
function WorkloadsTabPanel(props: { clusterId: string; matchState: WorkloadMatchState | undefined }) {
    const query = useClusterWorkloads(
        () => props.clusterId,
        () => ({ match_state: props.matchState, limit: 200 }),
    );
    return (
        <WorkloadsTab
            rows={query.data?.data}
            loading={query.isLoading}
            isError={query.isError}
            error={query.error}
        />
    );
}
