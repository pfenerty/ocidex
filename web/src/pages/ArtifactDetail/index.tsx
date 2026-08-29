import "~/components/DetailSection.css";
import { createSignal, For, Show } from "solid-js";
import { useParams, useSearchParams } from "@solidjs/router";
import {
    useArtifact,
    useArtifactVersions,
    useArtifactChangelog,
    useArtifactLicenseSummary,
    useArtifactUsages,
    useArtifactVulnSummary,
} from "~/api/queries";
import type { ArtifactVulnSortKey, VulnSeverityFilter } from "~/api/queries";
import type { SortDir } from "~/components/DataTable";
import { EmptyState } from "~/components/Feedback";
import { Skeleton, SkeletonHeader, SkeletonText } from "~/components/Skeleton";
import { Breadcrumb, ButtonGroup, Button, QueryBoundary, TabBar, createExpandedSet, type Crumb, type TabDef } from "~/components/ui";
import { artifactDisplayName } from "~/utils/format";
import { ArtifactHeader, ArtifactIdentity } from "./ArtifactHeader";
import { ArtifactBand, type ArtifactTab } from "./ArtifactBand";
import { VersionsTab } from "./VersionsTab";
import { LicensesTab } from "./LicensesTab";
import { ChangelogTab } from "./ChangelogTab";
import { RelationshipsTab } from "./RelationshipsTab";
import { VulnerabilitiesTab, SEVERITIES, SORT_KEYS as VULN_SORT_KEYS } from "./VulnerabilitiesTab";

const TABS: ArtifactTab[] = ["versions", "changelog", "licenses", "vulns", "relationships"];

/** Search params arrive as string | string[]; take the first value either way. */
function one(v: string | string[] | undefined): string | undefined {
    return Array.isArray(v) ? v[0] : v;
}

export default function ArtifactDetail() {
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
        return vulnSortBy() === "canonical_id" ? "asc" : "desc";
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
    });

    const licenseQuery = useArtifactLicenseSummary(() => params.id, {
        enabled: () => tab() === "licenses",
    });

    const usagesQuery = useArtifactUsages(() => params.id, {
        enabled: () => tab() === "relationships",
    });

    const vulnSummaryQuery = useArtifactVulnSummary(() => params.id);

    const tabs = (versionCount: number): TabDef<ArtifactTab>[] => [
        { id: "versions", label: `Versions (${versionCount})` },
        { id: "changelog", label: "Changelog" },
        { id: "licenses", label: "Licenses" },
        { id: "vulns", label: `Vulnerabilities (${vulnSummaryQuery.data?.summary.total ?? 0})` },
        { id: "relationships", label: "Relationships" },
    ];

    // Semver-vs-all is an ordering of the versions list, not a second place to
    // navigate to, so it renders as a segmented control (the idiom PackagesTab
    // already uses for tree/list) rather than as a second tab strip. Two tab
    // strips stacked on one page was the page's worst instance of depth.
    const MODES: { id: "semver" | "all"; label: string; title: string }[] = [
        { id: "semver", label: "Semver", title: "Only semver versions, ordered by semantic version" },
        { id: "all", label: "All", title: "All versions, ordered by build time" },
    ];

    const crumbs = (): Crumb[] => [
        { label: "Artifacts", href: "/artifacts" },
        { label: artifactQuery.isLoading ? <Skeleton width="6rem" inline /> : artifactQuery.data?.name },
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
                                <ArtifactHeader artifact={a()} breadcrumb={<Breadcrumb items={crumbs()} />} />

                                <ArtifactBand
                                    artifact={a()}
                                    isContainer={isContainer()}
                                    vulns={vulnSummaryQuery.data?.summary ?? undefined}
                                    ordering={effectiveMode()}
                                    active={tab()}
                                    onSelect={setTab}
                                />

                                <ArtifactIdentity artifact={a()} />

                                <TabBar tabs={tabs(a().versionCount)} active={tab()} onSelect={setTab} />

                                <Show when={hasSemver() && (tab() === "versions" || tab() === "changelog")}>
                                    <ButtonGroup class="mb-4">
                                        <For each={MODES}>
                                            {(m) => (
                                                <Button
                                                    size="sm"
                                                    active={effectiveMode() === m.id}
                                                    title={m.title}
                                                    aria-pressed={effectiveMode() === m.id}
                                                    onClick={() => selectMode(m.id)}
                                                >
                                                    {m.label}
                                                </Button>
                                            )}
                                        </For>
                                    </ButtonGroup>
                                </Show>

                                <Show when={tab() === "versions"}>
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
                                                availableArchitectures={d().availableArchitectures ?? []}
                                                selectedArch={selectedArch()}
                                                onArchChange={setSelectedArch}
                                                availableFlavors={d().availableFlavors ?? []}
                                                selectedFlavor={selectedFlavor()}
                                                onFlavorChange={setSelectedFlavor}
                                            />
                                        )}
                                    </QueryBoundary>
                                </Show>

                                <Show when={tab() === "licenses"}>
                                    <LicensesTab
                                        licenses={licenseQuery.data?.licenses}
                                        loading={licenseQuery.isFetching}
                                        isError={licenseQuery.isError}
                                        error={licenseQuery.error}
                                    />
                                </Show>

                                <Show when={tab() === "vulns"}>
                                    <VulnerabilitiesTab
                                        artifactId={params.id}
                                        summary={vulnSummaryQuery.data?.summary ?? undefined}
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
