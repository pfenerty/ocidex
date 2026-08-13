import "~/components/DetailSection.css";
import { createSignal, Show } from "solid-js";
import { A, useParams } from "@solidjs/router";
import {
    useArtifact,
    useArtifactVersions,
    useArtifactChangelog,
    useArtifactLicenseSummary,
    useArtifactUsages,
    useArtifactVulnSummary,
} from "~/api/queries";
import { ErrorBox, EmptyState } from "~/components/Feedback";
import { Skeleton, SkeletonHeader, SkeletonText } from "~/components/Skeleton";
import PurlLink from "~/components/PurlLink";
import CopyShareLink, { artifactLookupPath } from "~/components/CopyShareLink";
import { VulnSummaryBar } from "~/components/VulnBadge";
import { TypeBadge, SigningBadge } from "~/components/ui";
import { purlToRegistryUrl, purlTypeLabel } from "~/utils/purl";
import {
    artifactDisplayName,
    formatDateTime,
    relativeDate,
    plural,
} from "~/utils/format";
import { containerRegistryUrl, detectRegistry } from "~/utils/oci";
import { VersionsTab } from "./VersionsTab";
import { LicensesTab } from "./LicensesTab";
import { ChangelogTab } from "./ChangelogTab";
import { RelationshipsTab } from "./RelationshipsTab";

export default function ArtifactDetail() {
    const params = useParams<{ id: string }>();
    const [versionOffset, setVersionOffset] = createSignal(0);
    const [tab, setTab] = createSignal<
        "versions" | "changelog" | "licenses" | "relationships"
    >("versions");
    const [selectedArch, setSelectedArch] = createSignal<string | undefined>(
        "amd64",
    );
    const [selectedFlavor, setSelectedFlavor] = createSignal<string | undefined>(undefined);
    // undefined = auto (let the backend pick semver when available, else all).
    const [viewMode, setViewMode] = createSignal<"semver" | "all" | undefined>(undefined);
    const versionLimit = 25;

    const artifactQuery = useArtifact(() => params.id);

    // Image-specific chrome — signing/provenance, the registry link, the
    // architecture column — is meaningless for an uploaded binary or library and
    // renders as a row of em-dashes if left in. detectRegistry below already
    // branches on this; everything type-aware on this page goes through here.
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

    return (
        <>
            <div class="breadcrumb">
                <A href="/artifacts">Artifacts</A>
                <span class="separator">/</span>
                <span>
                    {artifactQuery.data?.name ?? (
                        <Skeleton width="6rem" style={{ display: "inline-block" }} />
                    )}
                </span>
            </div>

            <Show when={!artifactQuery.isLoading} fallback={<SkeletonHeader />}>
                <Show
                    when={!artifactQuery.isError}
                    fallback={<ErrorBox error={artifactQuery.error} />}
                >
                    <Show when={artifactQuery.data}>
                        {(a) => (
                            <>
                                <div class="page-header">
                                    <div class="page-header-row">
                                        <div>
                                            <h2>
                                                <Show
                                                    when={
                                                        a().type ===
                                                            "container" &&
                                                        detectRegistry(
                                                            a().name,
                                                        ) !== "redhat"
                                                    }
                                                    fallback={artifactDisplayName(
                                                        a(),
                                                    )}
                                                >
                                                    <a
                                                        href={containerRegistryUrl(
                                                            a().name,
                                                        )}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                    >
                                                        {artifactDisplayName(
                                                            a(),
                                                        )}
                                                    </a>
                                                </Show>
                                            </h2>
                                            <p class="text-muted">
                                                <TypeBadge type={a().type} />{" "}
                                                {plural(a().sbomCount, "SBOM")}
                                                {" · First tracked "}
                                                {relativeDate(a().createdAt)}
                                            </p>
                                        </div>
                                        <div class="btn-group">
                                            <Show
                                                when={
                                                    a().purl !== undefined &&
                                                    purlToRegistryUrl(
                                                        a().purl ?? "",
                                                    ) !== null
                                                        ? a().purl
                                                        : undefined
                                                }
                                            >
                                                {(purl) => (
                                                    <a
                                                        href={
                                                            purlToRegistryUrl(
                                                                purl(),
                                                            ) ?? ""
                                                        }
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        class="btn btn-sm btn-primary"
                                                    >
                                                        View on{" "}
                                                        {purlTypeLabel(
                                                            purl(),
                                                        ) ?? "Registry"}
                                                    </a>
                                                )}
                                            </Show>
                                            <A
                                                href={`/diff`}
                                                class="btn btn-sm"
                                            >
                                                Compare SBOMs
                                            </A>
                                            <CopyShareLink
                                                path={artifactLookupPath(a())}
                                            />
                                        </div>
                                    </div>
                                </div>

                                <div class="card mb-4">
                                    <div class="card-header">
                                        <h3>About this Artifact</h3>
                                    </div>
                                    <div class="detail-grid">
                                        <div class="detail-field">
                                            <span class="detail-label">
                                                Name
                                            </span>
                                            <span class="detail-value">
                                                {a().name}
                                            </span>
                                        </div>
                                        <div class="detail-field">
                                            <span class="detail-label">
                                                Type
                                            </span>
                                            <span class="detail-value">
                                                <TypeBadge type={a().type} />
                                            </span>
                                        </div>
                                        <Show when={isContainer()}>
                                            <div class="detail-field">
                                                <span class="detail-label">
                                                    Signing
                                                </span>
                                                <span class="detail-value">
                                                    <SigningBadge status={a().signingStatus} />
                                                </span>
                                            </div>
                                        </Show>
                                        <Show when={a().group}>
                                            <div class="detail-field">
                                                <span class="detail-label">
                                                    Group
                                                </span>
                                                <span class="detail-value">
                                                    {a().group}
                                                </span>
                                            </div>
                                        </Show>
                                        <Show when={a().purl}>
                                            {(purl) => (
                                                <div class="detail-field">
                                                    <span class="detail-label">
                                                        Package URL
                                                    </span>
                                                    <span class="detail-value">
                                                        <PurlLink
                                                            purl={purl()}
                                                            showBadge
                                                        />
                                                    </span>
                                                </div>
                                            )}
                                        </Show>
                                        <Show when={a().cpe}>
                                            <div class="detail-field">
                                                <span class="detail-label">
                                                    CPE
                                                </span>
                                                <span class="detail-value font-mono text-sm">
                                                    {a().cpe}
                                                </span>
                                            </div>
                                        </Show>
                                        <div class="detail-field">
                                            <span class="detail-label">
                                                First Tracked
                                            </span>
                                            <span class="detail-value">
                                                {formatDateTime(a().createdAt)}
                                            </span>
                                        </div>
                                    </div>
                                    <details class="mt-4">
                                        <summary
                                            class="text-muted text-sm"
                                            style={{ cursor: "pointer" }}
                                        >
                                            Internal ID
                                        </summary>
                                        <p
                                            class="font-mono text-sm mt-2"
                                            style={{
                                                "word-break": "break-all",
                                            }}
                                        >
                                            {a().id}
                                        </p>
                                    </details>
                                </div>

                                <VulnSummaryBar summary={vulnSummaryQuery.data?.summary ?? undefined} />

                                <div class="tab-bar">
                                    <button
                                        class={
                                            tab() === "versions" ? "active" : ""
                                        }
                                        onClick={() => setTab("versions")}
                                    >
                                        Versions ({a().versionCount})
                                    </button>
                                    <button
                                        class={
                                            tab() === "changelog"
                                                ? "active"
                                                : ""
                                        }
                                        onClick={() => setTab("changelog")}
                                    >
                                        Changelog
                                    </button>
                                    <button
                                        class={
                                            tab() === "licenses" ? "active" : ""
                                        }
                                        onClick={() => setTab("licenses")}
                                    >
                                        Licenses
                                    </button>
                                    <button
                                        class={
                                            tab() === "relationships"
                                                ? "active"
                                                : ""
                                        }
                                        onClick={() =>
                                            setTab("relationships")
                                        }
                                    >
                                        Relationships
                                    </button>
                                </div>

                                <Show
                                    when={
                                        hasSemver() &&
                                        (tab() === "versions" ||
                                            tab() === "changelog")
                                    }
                                >
                                    <div
                                        class="tab-bar"
                                        style={{ "margin-bottom": "0.75rem" }}
                                    >
                                        <button
                                            class={
                                                effectiveMode() === "semver"
                                                    ? "active"
                                                    : ""
                                            }
                                            onClick={() => selectMode("semver")}
                                            title="Only semver versions, ordered by semantic version"
                                        >
                                            Semver
                                        </button>
                                        <button
                                            class={
                                                effectiveMode() === "all"
                                                    ? "active"
                                                    : ""
                                            }
                                            onClick={() => selectMode("all")}
                                            title="All versions, ordered by build time"
                                        >
                                            All
                                        </button>
                                    </div>
                                </Show>

                                <Show when={tab() === "versions"}>
                                    <VersionsTab
                                        artifactId={params.id}
                                        isContainer={isContainer()}
                                        versions={versionsQuery.data?.data}
                                        pagination={
                                            versionsQuery.data?.pagination
                                        }
                                        loading={versionsQuery.isFetching}
                                        isError={versionsQuery.isError}
                                        error={versionsQuery.error}
                                        onPageChange={setVersionOffset}
                                    />
                                </Show>

                                <Show when={tab() === "changelog"}>
                                    <Show
                                        when={!changelogQuery.isLoading}
                                        fallback={<SkeletonText lines={8} />}
                                    >
                                        <Show
                                            when={!changelogQuery.isError}
                                            fallback={
                                                <ErrorBox
                                                    error={changelogQuery.error}
                                                />
                                            }
                                        >
                                            <Show
                                                when={changelogQuery.data}
                                                fallback={
                                                    <EmptyState
                                                        title="No changes detected"
                                                        message="At least two SBOMs are needed to generate a changelog. Ingest another SBOM for this artifact to see what changed."
                                                    />
                                                }
                                            >
                                                {(d) => (
                                                    <ChangelogTab
                                                        entries={d().entries}
                                                        availableArchitectures={
                                                            d()
                                                                .availableArchitectures ??
                                                            []
                                                        }
                                                        selectedArch={selectedArch()}
                                                        onArchChange={
                                                            setSelectedArch
                                                        }
                                                        availableFlavors={
                                                            d()
                                                                .availableFlavors ??
                                                            []
                                                        }
                                                        selectedFlavor={selectedFlavor()}
                                                        onFlavorChange={
                                                            setSelectedFlavor
                                                        }
                                                    />
                                                )}
                                            </Show>
                                        </Show>
                                    </Show>
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
                    </Show>
                </Show>
            </Show>
        </>
    );
}
