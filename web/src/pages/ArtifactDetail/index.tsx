import "~/components/DetailSection.css";
import { createSignal, For, Show } from "solid-js";
import { useParams } from "@solidjs/router";
import {
    useArtifact,
    useArtifactVersions,
    useArtifactChangelog,
    useArtifactLicenseSummary,
    useArtifactUsages,
    useArtifactVulnSummary,
} from "~/api/queries";
import { EmptyState } from "~/components/Feedback";
import { Skeleton, SkeletonHeader, SkeletonText } from "~/components/Skeleton";
import { Breadcrumb, ButtonGroup, Button, QueryBoundary, TabBar, type Crumb, type TabDef } from "~/components/ui";
import { artifactDisplayName } from "~/utils/format";
import { ArtifactHeader, ArtifactIdentity } from "./ArtifactHeader";
import { ArtifactBand, type ArtifactTab } from "./ArtifactBand";
import { VersionsTab } from "./VersionsTab";
import { LicensesTab } from "./LicensesTab";
import { ChangelogTab } from "./ChangelogTab";
import { RelationshipsTab } from "./RelationshipsTab";

export default function ArtifactDetail() {
    const params = useParams<{ id: string }>();
    const [versionOffset, setVersionOffset] = createSignal(0);
    const [tab, setTab] = createSignal<ArtifactTab>("versions");
    const [selectedArch, setSelectedArch] = createSignal<string | undefined>("amd64");
    const [selectedFlavor, setSelectedFlavor] = createSignal<string | undefined>(undefined);
    // undefined = auto (let the backend pick semver when available, else all).
    const [viewMode, setViewMode] = createSignal<"semver" | "all" | undefined>(undefined);
    const versionLimit = 25;

    const artifactQuery = useArtifact(() => params.id);

    // Image-specific chrome — signing/provenance, the registry link, the
    // architecture column — is meaningless for an uploaded binary or library and
    // renders as a row of em-dashes if left in. detectRegistry already branches
    // on this; everything type-aware on this page goes through here.
    const isContainer = () => artifactQuery.data?.type === "container";

    const versionsQuery = useArtifactVersions(
        () => params.id,
        () => ({ limit: versionLimit, offset: versionOffset(), mode: viewMode() }),
    );

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
