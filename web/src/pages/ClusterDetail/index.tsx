import "./ClusterDetail.css";
import { Show, createEffect, createSignal, on } from "solid-js";
import { A, useParams, useSearchParams } from "@solidjs/router";
import { Breadcrumb, Button, Card, DetailField, DetailGrid, EntryLine, PageHeader, QueryBoundary, TabBar, type TabDef } from "~/components/ui";
import { plural } from "~/utils/format";
import { forgetInstallKey } from "./installKey";
import { SkeletonHeader } from "~/components/Skeleton";
import { StalenessPill } from "../Clusters";
import {
    useCluster,
    useClusterImages,
    useClusterNamespaces,
    useClusterWorkloads,
    useRefreshClusterInventory,
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
import { AgentTab } from "./AgentTab";
import type { Cluster } from "~/api/client";

const TABS = ["overview", "workloads", "vulnerabilities", "gaps", "agent"] as const;
type Tab = (typeof TABS)[number];

const tabs: TabDef<Tab>[] = [
    { id: "overview", label: "Overview" },
    { id: "workloads", label: "Workloads" },
    { id: "vulnerabilities", label: "Vulnerabilities", title: "Vulnerabilities in the images this cluster runs" },
    { id: "gaps", label: "Gaps", title: "Containers OCIDex cannot assess, and why" },
    { id: "agent", label: "Agent", title: "Push history, credentials, settings and retiring the cluster" },
];

/** Tabs that exist before the first snapshot: setup, and the agent itself. */
const PRE_REPORT_TABS: readonly Tab[] = ["overview", "agent"];

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

    // Before the first snapshot there is nothing to count or list, and four
    // zero tiles over three empty tabs read as a clean cluster (ADR-044 K5,
    // ocidex-70eo.13). Until then the page is the Overview's setup card alone.
    // Undefined while loading, which hides the band rather than flashing zeros.
    const reported = () => (clusterQuery.data?.lastSeenAt ?? "") !== "";

    // The first snapshot arriving while this page is open (ocidex-70eo.6):
    // say so, drop the one-time key, and re-read the inventory queries, which
    // were fetched empty and would otherwise wait out their own staleness.
    const refreshInventory = useRefreshClusterInventory();
    const [justConnected, setJustConnected] = createSignal(false);
    let sawUnreported = false;
    createEffect(
        on(
            () => clusterQuery.data?.lastSeenAt,
            (seen) => {
                if (clusterQuery.data === undefined) return;
                if ((seen ?? "") === "") {
                    sawUnreported = true;
                    return;
                }
                if (sawUnreported) {
                    sawUnreported = false;
                    setJustConnected(true);
                    forgetInstallKey(params.id);
                }
                void refreshInventory(params.id);
            },
            { defer: true },
        ),
    );
    const visibleTabs = () => (reported() ? tabs : tabs.filter((t) => PRE_REPORT_TABS.includes(t.id)));

    const tab = (): Tab => {
        const t = TABS.find((candidate) => candidate === one(searchParams.tab)) ?? "overview";
        return reported() || PRE_REPORT_TABS.includes(t) ? t : "overview";
    };
    // A hand-edited URL can say anything; an unrecognised state is dropped
    // rather than forwarded, so the table shows everything instead of nothing.
    const matchState = (): WorkloadMatchState | undefined => {
        const raw = one(searchParams.matchState);
        return MATCH_STATES.find((candidate) => candidate === raw);
    };

    // The band's counts come from the unfiltered workload query, so they stay
    // cluster-wide however a tab below has narrowed its own view (ADR-044 K5).
    const coverageQuery = useClusterWorkloads(() => params.id, () => ({ limit: 1 }));

    return (
        <>
            <QueryBoundary
                query={clusterQuery}
                breadcrumb={<Breadcrumb items={[{ label: "Clusters", href: "/clusters" }]} />}
                loading={<SkeletonHeader />}
            >
                {(cluster) => (
                    <PageHeader
                        breadcrumb={
                            <Breadcrumb
                                items={[
                                    { label: "Clusters", href: "/clusters" },
                                    { label: cluster().name },
                                ]}
                            />
                        }
                        eyebrow={<EntryLine kind="Cluster" id={cluster().id} />}
                        title={cluster().name}
                        subtitle={cluster().description ?? "Kubernetes cluster inventory"}
                        footer={
                            <DetailGrid>
                                <DetailField label="Namespace" when={cluster().namespaceName}>
                                    {cluster().namespaceName}
                                </DetailField>
                                <DetailField label="Agent health">
                                    <StalenessPill lastSeenAt={cluster().lastSeenAt} health={cluster().health} />
                                </DetailField>
                                <DetailField label="Agent" when={cluster().agent?.version}>
                                    {cluster().agent?.version}
                                </DetailField>
                                <DetailField label="Kubernetes" when={cluster().agent?.kubernetesVersion}>
                                    {cluster().agent?.kubernetesVersion}
                                    <Show when={cluster().agent?.nodeCount}>
                                        {(n) => <span class="text-muted"> · {plural(n(), "node")}</span>}
                                    </Show>
                                </DetailField>
                                <DetailField
                                    label="Reports every"
                                    when={cluster().agent?.reportIntervalSeconds !== undefined}
                                >
                                    {intervalLabel(cluster().agent?.reportIntervalSeconds)}
                                </DetailField>
                                <DetailField label="Agent pod" when={cluster().agent?.podName} valueClass="font-mono text-sm">
                                    {cluster().agent?.podNamespace}/{cluster().agent?.podName}
                                </DetailField>
                                <DetailField label="Cluster ID" valueClass="font-mono text-sm">
                                    {cluster().id}
                                </DetailField>
                            </DetailGrid>
                        }
                    />
                )}
            </QueryBoundary>

            <Show when={clusterQuery.data}>{(c) => <HealthBanners cluster={c()} />}</Show>

            <Show when={justConnected() && clusterQuery.data}>
                {(c) => (
                    <Card tone="success" class="mb-4" data-testid="just-connected">
                        <strong>Connected.</strong>{" "}
                        <Show when={coverageQuery.data}>
                            {(d) => <>{plural(d().coverage.total, "container")} </>}
                        </Show>
                        <Show when={c().agent?.nodeCount}>{(n) => <>on {plural(n(), "node")} </>}</Show>
                        <Show when={c().agent?.kubernetesVersion}>{(v) => <>· Kubernetes {v()} </>}</Show>
                        <Show when={c().agent?.version}>{(v) => <>· agent {v()}</>}</Show>
                        <Button size="sm" class="ml-2" onClick={() => setJustConnected(false)}>
                            Dismiss
                        </Button>
                    </Card>
                )}
            </Show>

            <Show when={reported() && coverageQuery.data}>
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
                tabs={visibleTabs()}
                active={tab()}
                onSelect={(id) => {
                    // Filters belong to the tab that owns them; carrying a
                    // matchState onto the vulnerability list would silently
                    // apply to nothing.
                    setSearchParams({
                        tab: id,
                        matchState: undefined,
                        k8sNamespace: undefined,
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
                                lastSeenAt={clusterQuery.data?.lastSeenAt}
                                // Defaults to on server-side; treated as off
                                // only while the cluster is still loading, so
                                // the line never claims ingest is running
                                // before it knows.
                                autoIngest={clusterQuery.data?.autoIngest ?? false}
                                namespaceId={clusterQuery.data?.namespaceId}
                                health={clusterQuery.data?.health}
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
                            <GapsTab
                                clusterId={params.id}
                                namespace={clusterQuery.data?.namespaceName ?? ""}
                                coverage={data().coverage}
                            />
                        </Show>
                        <Show when={tab() === "agent" && clusterQuery.data}>
                            {(c) => <AgentTab cluster={c()} />}
                        </Show>
                    </>
                )}
            </Show>
        </>
    );
}

function intervalLabel(seconds: number | undefined): string {
    if (seconds === undefined) return "";
    if (seconds === 0) return "once (Job)";
    return seconds % 60 === 0 ? `${seconds / 60}m` : `${seconds}s`;
}

/**
 * HealthBanners states a problem before anything else on the page
 * (ocidex-70eo.7): a stale cluster's inventory looks exactly like a current
 * one, and a refused agent looks like a quiet one, unless something says so.
 * Never-reported needs no banner: the whole Overview is its setup card.
 */
function HealthBanners(props: { cluster: Cluster }) {
    const h = () => props.cluster.health;
    return (
        <>
            <Show when={h().state === "erroring" && (props.cluster.lastSeenAt ?? "") !== ""}>
                <Card tone="danger" class="mb-3" data-testid="banner-erroring">
                    <strong>The agent is reporting, and OCIDex is refusing it.</strong> {h().reason} The inventory
                    below is from the last accepted snapshot. <A href={`/clusters/${props.cluster.id}?tab=agent`}>See recent pushes</A>
                </Card>
            </Show>
            <Show when={h().state === "stale"}>
                <Card tone="warning" class="mb-3" data-testid="banner-stale">
                    <strong>This inventory may not be what is running now.</strong> {h().reason} Check{" "}
                    <code>kubectl -n {props.cluster.agent?.podNamespace ?? "ocidex-agent"} logs deploy/ocidex-k8s-agent</code>.
                </Card>
            </Show>
            <Show when={h().state === "paused"}>
                <Card class="mb-3" data-testid="banner-paused">
                    <strong>Paused.</strong> {h().reason} Resume it from the Agent tab.
                </Card>
            </Show>
            <Show when={(props.cluster.agent?.versionSkew ?? "") !== ""}>
                <Card tone="warning" class="mb-3" data-testid="banner-skew">
                    {props.cluster.agent?.versionSkew}
                </Card>
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
        "k8sNamespace",
        "workloadName",
        "containerName",
        "imageRef",
        "matchState",
        "podCount",
        "lastSeenAt",
        "vulnCount",
    ],
    image: ["imageRef", "matchState", "workloadCount", "podCount", "lastSeenAt", "vulnCount"],
};

/**
 * Worst findings first, in both groupings.
 *
 * The old default was namespace ascending, which is alphabetical rather than
 * actionable: it opened on whatever happens to be called "argocd". The first
 * screen should be the one worth acting on.
 */
const DEFAULT_SORT = "vulnCount";

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
    const k8sNamespace = () => one(props.searchParams.k8sNamespace) ?? "";
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
        matchState: props.matchState,
        ...(k8sNamespace() === "" ? {} : { k8sNamespace: k8sNamespace() }),
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
                    props.setSearchParams({ k8sNamespace: value, offset: undefined })
                }
                onMatchStateChange={(value) =>
                    props.setSearchParams({ matchState: value, offset: undefined })
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
        return sortBy() === "canonicalId" ? "asc" : "desc";
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
