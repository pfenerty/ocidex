import "~/components/DetailSection.css";
import { createSignal, Show } from "solid-js";
import { A, useParams } from "@solidjs/router";
import {
    useArtifact,
    useArtifactVersions,
    useArtifactChangelog,
    useArtifactLicenseSummary,
    useArtifactVulnSummary,
} from "~/api/queries";
import { Loading, ErrorBox, EmptyState } from "~/components/Feedback";
import PurlLink from "~/components/PurlLink";
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

export default function ArtifactDetail() {
    const params = useParams<{ id: string }>();
    const [versionOffset, setVersionOffset] = createSignal(0);
    const [tab, setTab] = createSignal<"versions" | "changelog" | "licenses">(
        "versions",
    );
    const [selectedArch, setSelectedArch] = createSignal<string | undefined>(
        "amd64",
    );
    const [selectedFlavor, setSelectedFlavor] = createSignal<string | undefined>(undefined);
    const versionLimit = 25;

    const artifactQuery = useArtifact(() => params.id);

    const versionsQuery = useArtifactVersions(
        () => params.id,
        () => ({ limit: versionLimit, offset: versionOffset() }),
    );

    const changelogQuery = useArtifactChangelog(() => params.id, {
        enabled: () => tab() === "changelog",
        arch: selectedArch,
        flavor: selectedFlavor,
    });

    const licenseQuery = useArtifactLicenseSummary(() => params.id, {
        enabled: () => tab() === "licenses",
    });

    const vulnSummaryQuery = useArtifactVulnSummary(() => params.id);

    return (
        <>
            <div class="breadcrumb">
                <A href="/artifacts">Artifacts</A>
                <span class="separator">/</span>
                <span>{artifactQuery.data?.name ?? params.id}</span>
            </div>

            <Show when={!artifactQuery.isLoading} fallback={<Loading />}>
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
                                        <div class="detail-field">
                                            <span class="detail-label">
                                                Signing
                                            </span>
                                            <span class="detail-value">
                                                <SigningBadge status={a().signingStatus} />
                                            </span>
                                        </div>
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
                                </div>

                                <Show when={tab() === "versions"}>
                                    <VersionsTab
                                        artifactId={params.id}
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
                                        fallback={<Loading />}
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
                            </>
                        )}
                    </Show>
                </Show>
            </Show>
        </>
    );
}
