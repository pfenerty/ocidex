import type { ArtifactDetail } from "~/api/client";
import "~/components/DetailSection.css";
import { createSignal, Show } from "solid-js";
import { useParams, useSearchParams } from "@solidjs/router";
import NotFound from "~/pages/NotFound";
import {
    useArtifact,
    useArtifactVersions,
    useArtifactChangelog,
    useArtifactLicenseSummary,
    useArtifactUsages,
    useArtifactVulnSummary,
    useArtifactWorkloads,
    useDashboardStats,
} from "~/api/queries";
import { useAuth } from "~/context/auth";
import { StatusPill } from "~/components/ui";
import { RunningTab, clusterNames } from "./RunningTab";
import type { ArtifactVulnSortKey, VulnSeverityFilter } from "~/api/queries";
import type { SortDir } from "~/components/DataTable";
import { EmptyState } from "~/components/Feedback";
import { Skeleton, SkeletonHeader, SkeletonText } from "~/components/Skeleton";
import { Breadcrumb, QueryBoundary, Segmented, TabBar, createExpandedSet, type Crumb, type TabDef } from "~/components/ui";
import { artifactDisplayName, plural } from "~/utils/format";
import { ArtifactHeader, ArtifactIdentity } from "./ArtifactHeader";
import { ArtifactBand, type ArtifactTab } from "./ArtifactBand";
import { VersionChart, severityPoints } from "./ArtifactChange";
import { criticalChange } from "~/utils/versionDelta";
import { StatBlock, type StatRow } from "./StatBlock";
import { isShiny } from "~/components/Shiny";
import { VersionsTab } from "./VersionsTab";
import { LicensesTab } from "./LicensesTab";
import { ChangelogTab } from "./ChangelogTab";
import { RelationshipsTab } from "./RelationshipsTab";
import { VulnerabilitiesTab, SEVERITIES, SORT_KEYS as VULN_SORT_KEYS } from "./VulnerabilitiesTab";

const TABS: ArtifactTab[] = ["versions", "changelog", "licenses", "vulns", "relationships", "running"];

/** Search params arrive as string | string[]; take the first value either way. */
function one(v: string | string[] | undefined): string | undefined {
    return Array.isArray(v) ? v[0] : v;
}

function ArtifactDetailPage() {
    const params = useParams<{ id: string }>();
    const [searchParams, setSearchParams] = useSearchParams();
    const [versionOffset, setVersionOffset] = createSignal(0);

    /* The tab lives in a search param, not component state, so the reverse trail
       from /vulnerabilities/:id can land directly on this artifact's affected
       versions — ?tab=vulns&vuln=CVE-… — and so a filtered view is a link. */
    const tab = (): ArtifactTab => {
        const t = one(searchParams.tab);
        return TABS.find((candidate) => candidate === t) ?? "versions";
    };
    // Switching tabs drops the vuln list's filter/sort/page: they mean nothing
    // to the other tabs and would otherwise reappear on the way back.
    const setTab = (next: ArtifactTab) =>
        setSearchParams({
            tab: next === "versions" ? undefined : next,
            severity: undefined,
            vuln: undefined,
            sort: undefined,
            dir: undefined,
            offset: undefined,
        });

    // A hand-edited URL can say anything; an unrecognised value is dropped
    // rather than forwarded, so the list shows everything instead of nothing.
    const vulnSeverity = (): VulnSeverityFilter | undefined => {
        const raw = one(searchParams.severity);
        return SEVERITIES.find((candidate) => candidate === raw);
    };
    // ?vuln= is passed through unvalidated on purpose — it is an advisory id
    // from another page, and the server decides whether it matches anything.
    const vulnFilter = (): string | undefined => {
        const raw = one(searchParams.vuln);
        return raw !== undefined && raw !== "" ? raw : undefined;
    };
    const vulnSortBy = (): ArtifactVulnSortKey => {
        const raw = one(searchParams.sort);
        return VULN_SORT_KEYS.find((candidate) => candidate === raw) ?? "severity";
    };
    // Severity's useful default is worst-first, the opposite of what every
    // other column wants.
    const vulnSortDir = (): SortDir => {
        const raw = one(searchParams.dir);
        if (raw === "asc" || raw === "desc") return raw;
        return vulnSortBy() === "canonicalId" ? "asc" : "desc";
    };
    const vulnOffset = () => {
        const parsed = Number(one(searchParams.offset));
        return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
    };
    const vulnExpanded = createExpandedSet();
    const [selectedArch, setSelectedArch] = createSignal<string | undefined>("amd64");
    const [selectedFlavor, setSelectedFlavor] = createSignal<string | undefined>(undefined);
    // undefined = auto (let the backend pick semver when available, else all).
    const [viewMode, setViewMode] = createSignal<"semver" | "all" | undefined>(undefined);
    // undefined = the mode's own ordering (semver precedence, or build time).
    // Kept in component state rather than a search param: unlike the vulns tab
    // there is no inbound link that needs to name a versions sort.
    const [versionSortBy, setVersionSortBy] = createSignal<"severity" | undefined>(undefined);
    const [versionSortDir, setVersionSortDir] = createSignal<SortDir>("desc");
    const versionLimit = 25;

    // The changelog is paged (ocidex-7gf7.4): an entry is a full component diff
    // between two consecutive versions, and an artifact with a thousand versions
    // was returning a thousand of them in one response.
    //
    // The page and the tree/list toggle live here rather than inside
    // ChangelogTab because QueryBoundary renders its child with <Show keyed>:
    // a new page is a new data identity, so the tab remounts and anything it
    // held locally is gone. Above the boundary, both survive.
    const changelogLimit = 20;
    const [changelogOffset, setChangelogOffset] = createSignal(0);
    const [changelogView, setChangelogView] = createSignal<"tree" | "list">("tree");

    const artifactQuery = useArtifact(() => params.id);

    // Image-specific chrome — signing/provenance, the registry link, the
    // architecture column — is meaningless for an uploaded binary or library and
    // renders as a row of em-dashes if left in. detectRegistry already branches
    // on this; everything type-aware on this page goes through here.
    const isContainer = () => artifactQuery.data?.type === "container";

    const versionsQuery = useArtifactVersions(
        () => params.id,
        () => ({
            limit: versionLimit,
            offset: versionOffset(),
            mode: viewMode(),
            sort: versionSortBy(),
            dir: versionSortBy() === undefined ? undefined : versionSortDir(),
        }),
    );

    // The newest page in the default order, for the verdict and the chart. Same
    // key as the table's default view, so it costs no request until the reader
    // sorts or pages away, and the verdict then stays put.
    const latestVersionsQuery = useArtifactVersions(
        () => params.id,
        () => ({ limit: versionLimit, offset: 0, mode: viewMode() }),
    );
    const latestPoints = () => severityPoints(latestVersionsQuery.data?.data);
    // The tile counts the headline version, which need not be the table's
    // first row (a newer prerelease sorts above it), so the change is looked
    // up by that version rather than taken from the top.
    const headlineChange = () => {
        const version = vulnSummaryQuery.data?.subjectVersion;
        return version === undefined || version === "" ? undefined : criticalChange(latestPoints(), version);
    };

    // Catalog maximums come from the warmed stats snapshot; until it is warm
    // there is nothing to scale against and the block stays hidden.
    const catalogStats = useDashboardStats();
    const statRows = (a: ArtifactDetail): StatRow[] => {
        const m = catalogStats.data?.warming === false ? catalogStats.data.artifactMaxima : undefined;
        if (m === undefined) return [];
        const vulns = vulnSummaryQuery.data?.summary;
        const latestArch = latestVersionsQuery.data?.data[0]?.architectures?.length;
        return [
            { label: "PKG", title: "Packages in the latest version", value: a.packageCount, max: m.packages },
            { label: "VER", title: "Versions", value: a.versionCount, max: m.versions },
            { label: "SBM", title: "SBOMs", value: a.sbomCount, max: m.sboms },
            ...(isContainer()
                ? [{ label: "ARC", title: "Architectures in the latest version", value: latestArch, max: m.architectures }]
                : []),
            { label: "CRT", title: "Critical findings, latest version", value: vulns?.critical, max: m.critical, tone: "critical" },
            { label: "HGH", title: "High findings, latest version", value: vulns?.high, max: m.high, tone: "high" },
        ];
    };

    // Sorting reorders the whole result set server-side, so the current page
    // number means nothing afterwards.
    const sortVersions = (key: string, dir: SortDir) => {
        setVersionSortBy(key === "severity" ? "severity" : undefined);
        setVersionSortDir(dir);
        setVersionOffset(0);
    };

    // The versions query always runs, so it's the source of truth for whether
    // the artifact has semver versions and which mode the backend resolved to.
    const hasSemver = () => versionsQuery.data?.hasSemver ?? false;
    const effectiveMode = (): "semver" | "all" => {
        const explicit = viewMode();
        if (explicit !== undefined) return explicit;
        return versionsQuery.data?.resolvedMode === "semver" ? "semver" : "all";
    };
    const selectMode = (m: "semver" | "all") => {
        setViewMode(m);
        setVersionOffset(0);
    };

    const changelogQuery = useArtifactChangelog(() => params.id, {
        enabled: () => tab() === "changelog",
        arch: selectedArch,
        flavor: selectedFlavor,
        mode: viewMode,
        limit: () => changelogLimit,
        offset: changelogOffset,
    });

    // Changing the timeline reorders it, so the page number no longer refers to
    // anything — the same reason sortVersions resets versionOffset.
    const selectChangelogArch = (arch: string) => {
        setSelectedArch(arch);
        setChangelogOffset(0);
    };
    const selectChangelogFlavor = (flavor: string) => {
        setSelectedFlavor(flavor);
        setChangelogOffset(0);
    };

    const licenseQuery = useArtifactLicenseSummary(() => params.id, {
        enabled: () => tab() === "licenses",
    });

    const usagesQuery = useArtifactUsages(() => params.id, {
        enabled: () => tab() === "relationships",
    });

    const vulnSummaryQuery = useArtifactVulnSummary(() => params.id);

    // Where it runs (ocidex-70eo.8). Signed-in only: inventory is never
    // public, and this page is.
    const { user } = useAuth();
    const signedIn = () => user() !== undefined;
    const runningQuery = useArtifactWorkloads(() => params.id, signedIn);
    const runningClusters = () => clusterNames(runningQuery.data ?? []);

    const tabs = (versionCount: number): TabDef<ArtifactTab>[] => [
        { id: "versions", label: `Versions (${versionCount})` },
        { id: "changelog", label: "Changelog" },
        { id: "licenses", label: "Licenses" },
        // No count: the band's tile counts one SBOM of the latest version,
        // while the tab lists the newest SBOM of each recent version, so any
        // number here disagreed with the rows under it. The tab states its own
        // total; fetching that list just for a label is the heavy query.
        { id: "vulns", label: "Vulnerabilities" },
        { id: "relationships", label: "Relationships" },
        ...(signedIn()
            ? [{ id: "running" as const, label: `Running (${(runningQuery.data ?? []).length})` }]
            : []),
    ];

    // Semver-vs-all is an ordering of the versions list, not a second place to
    // navigate to, so it renders as a segmented control (the idiom PackagesTab
    // already uses for tree/list) rather than as a second tab strip. Two tab
    // strips stacked on one page was the page's worst instance of depth.
    const MODES: { id: "semver" | "all"; label: string; title: string }[] = [
        { id: "semver", label: "Semver", title: "Only semver versions, ordered by semantic version" },
        { id: "all", label: "All", title: "All versions, highest version first" },
    ];

    const crumbs = (): Crumb[] => [
        { label: "Artifacts", href: "/artifacts" },
        // The same group/name the title and the list use (ocidex-nps9.28).
        {
            label: artifactQuery.isLoading ? (
                <Skeleton width="6rem" inline />
            ) : artifactQuery.data !== undefined ? (
                artifactDisplayName(artifactQuery.data)
            ) : undefined,
        },
    ];

    return (
        <>
            <QueryBoundary
                query={artifactQuery}
                breadcrumb={<Breadcrumb items={crumbs()} />}
                loading={<SkeletonHeader />}
                empty={<EmptyState title="Artifact not found." message="This artifact may have been removed, or the link may be wrong." />}
            >
                        {(a) => (
                            <>
                                <ArtifactHeader artifact={a()} breadcrumb={<Breadcrumb items={crumbs()} />} points={latestPoints()} change={headlineChange()} shiny={vulnSummaryQuery.data !== undefined && isShiny(vulnSummaryQuery.data.matched, vulnSummaryQuery.data.summary?.total)} />

                                <Show when={runningClusters().length > 0}>
                                    <p class="mb-3" data-testid="running-in">
                                        <button type="button" class="link-button" onClick={() => setTab("running")}>
                                            <StatusPill variant="success" title={runningClusters().join(", ")}>
                                                Running in {runningClusters().length === 1 ? "1 cluster" : `${runningClusters().length} clusters`}
                                            </StatusPill>
                                        </button>{" "}
                                        <span class="text-muted text-sm">{runningClusters().join(", ")}</span>
                                    </p>
                                </Show>

                                <ArtifactBand
                                    artifact={a()}
                                    isContainer={isContainer()}
                                    vulns={vulnSummaryQuery.data?.summary}
                                    vulnsVersion={vulnSummaryQuery.data?.subjectVersion}
                                    vulnsCounted={vulnSummaryQuery.data?.countedSbom}
                                    vulnsChange={headlineChange()}
                                    vulnsMatched={vulnSummaryQuery.data?.matched}
                                    ordering={effectiveMode()}
                                    active={tab()}
                                    onSelect={setTab}
                                />

                                <ArtifactIdentity artifact={a()} stats={<StatBlock rows={statRows(a())} />} />

                                <TabBar tabs={tabs(a().versionCount)} active={tab()} onSelect={setTab} />

                                <Show when={hasSemver() && (tab() === "versions" || tab() === "changelog")}>
                                    <Segmented
                                        class="mb-4"
                                        label="Version order"
                                        options={MODES}
                                        value={effectiveMode()}
                                        onChange={selectMode}
                                    />
                                </Show>

                                <Show when={tab() === "versions"}>
                                    {/* Semver mode drops every other version, so the
                                        count it hides is said rather than left to
                                        the tab's total to contradict (ocidex-nps9.9). */}
                                    <Show
                                        when={
                                            effectiveMode() === "semver" && versionsQuery.data !== undefined
                                                ? a().versionCount - versionsQuery.data.pagination.total
                                                : 0
                                        }
                                    >
                                        {(hidden) => (
                                            <Show when={hidden() > 0}>
                                                <p class="text-muted text-sm mb-4">
                                                    {plural(versionsQuery.data?.pagination.total ?? 0, "semver release")} ·{" "}
                                                    {plural(hidden(), "other build")} hidden.{" "}
                                                    <button type="button" class="link-button" onClick={() => selectMode("all")}>
                                                        Show all
                                                    </button>
                                                </p>
                                            </Show>
                                        )}
                                    </Show>
                                    <VersionChart points={latestPoints()} />
                                    <VersionsTab
                                        artifactId={params.id}
                                        isContainer={isContainer()}
                                        versions={versionsQuery.data?.data}
                                        pagination={versionsQuery.data?.pagination}
                                        loading={versionsQuery.isFetching}
                                        isError={versionsQuery.isError}
                                        error={versionsQuery.error}
                                        onPageChange={setVersionOffset}
                                        sortBy={versionSortBy()}
                                        sortDir={versionSortDir()}
                                        onSort={sortVersions}
                                        running={runningQuery.data}
                                    />
                                </Show>

                                <Show when={tab() === "changelog"}>
                                    <QueryBoundary
                                        query={changelogQuery}
                                        loading={<SkeletonText lines={8} />}
                                        empty={
                                            <EmptyState
                                                title="No changes detected"
                                                message="At least two SBOMs are needed to generate a changelog. Ingest another SBOM for this artifact to see what changed."
                                            />
                                        }
                                    >
                                        {(d) => (
                                            <ChangelogTab
                                                entries={d().entries}
                                                pagination={d().pagination}
                                                onPageChange={setChangelogOffset}
                                                availableArchitectures={d().availableArchitectures ?? []}
                                                selectedArch={selectedArch()}
                                                onArchChange={selectChangelogArch}
                                                availableFlavors={d().availableFlavors ?? []}
                                                selectedFlavor={selectedFlavor()}
                                                onFlavorChange={selectChangelogFlavor}
                                                viewMode={changelogView()}
                                                onViewModeChange={setChangelogView}
                                            />
                                        )}
                                    </QueryBoundary>
                                </Show>

                                <Show when={tab() === "licenses"}>
                                    <LicensesTab
                                        licenses={licenseQuery.data?.licenses}
                                        sbomId={licenseQuery.data?.sbomId}
                                        subjectVersion={licenseQuery.data?.subjectVersion}
                                        loading={licenseQuery.isFetching}
                                        isError={licenseQuery.isError}
                                        error={licenseQuery.error}
                                    />
                                </Show>

                                <Show when={tab() === "vulns"}>
                                    <VulnerabilitiesTab
                                        artifactId={params.id}
                                        summary={vulnSummaryQuery.data?.summary}
                                        severity={vulnSeverity()}
                                        vuln={vulnFilter()}
                                        sortBy={vulnSortBy()}
                                        sortDir={vulnSortDir()}
                                        offset={vulnOffset()}
                                        expanded={vulnExpanded}
                                        onSeverityChange={(severity) =>
                                            setSearchParams({ severity, offset: undefined })
                                        }
                                        onClearVuln={() => setSearchParams({ vuln: undefined, offset: undefined })}
                                        onSort={(sortKey, dir) =>
                                            setSearchParams({ sort: sortKey, dir, offset: undefined })
                                        }
                                        onPageChange={(offset) =>
                                            setSearchParams({ offset: offset === 0 ? undefined : String(offset) })
                                        }
                                    />
                                </Show>

                                <Show when={tab() === "running"}>
                                    <RunningTab
                                        rows={runningQuery.data}
                                        loading={runningQuery.isFetching}
                                        isError={runningQuery.isError}
                                        error={runningQuery.error}
                                    />
                                </Show>

                                <Show when={tab() === "relationships"}>
                                    <RelationshipsTab
                                        artifactName={artifactDisplayName(a())}
                                        relations={usagesQuery.data?.usages}
                                        loading={usagesQuery.isFetching}
                                        isError={usagesQuery.isError}
                                        error={usagesQuery.error}
                                    />
                                </Show>
                            </>
                        )}
            </QueryBoundary>
        </>
    );
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * An id that is not a UUID can never name an artifact: the API answers 422,
 * which the page used to show raw. It is a mistyped or guessed URL, so it gets
 * the not-found page, which offers search and a did-you-mean.
 */
export default function ArtifactDetail() {
    const params = useParams<{ id: string }>();
    return (
        <Show when={UUID_RE.test(params.id)} fallback={<NotFound />}>
            <ArtifactDetailPage />
        </Show>
    );
}
