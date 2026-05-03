import { createSignal, Show } from "solid-js";
import { A, useParams } from "@solidjs/router";
import {
    useArtifact,
    useArtifactVersions,
    useArtifactChangelog,
    useArtifactLicenseSummary,
} from "~/api/queries";
import { Loading, ErrorBox, EmptyState } from "~/components/Feedback";
import PurlLink from "~/components/PurlLink";
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
        undefined,
    );
    const versionLimit = 25;

    const artifactQuery = useArtifact(() => params.id);

    const versionsQuery = useArtifactVersions(
        () => params.id,
        () => ({ limit: versionLimit, offset: versionOffset() }),
    );

    const changelogQuery = useArtifactChangelog(() => params.id, {
        enabled: () => tab() === "changelog",
        arch: selectedArch,
    });

    const licenseQuery = useArtifactLicenseSummary(() => params.id, {
        enabled: () => tab() === "licenses",
    });

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
                                                <span class="badge">
                                                    {a().type}
                                                </span>{" "}
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

                                <div class="card mb-md">
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
                                                {a().type}
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
                                                <span class="detail-value mono text-sm">
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
                                    <details class="mt-md">
                                        <summary
                                            class="text-muted text-sm"
                                            style={{ cursor: "pointer" }}
                                        >
                                            Internal ID
                                        </summary>
                                        <p
                                            class="mono text-sm mt-sm"
                                            style={{
                                                "word-break": "break-all",
                                            }}
                                        >
                                            {a().id}
                                        </p>
                                    </details>
                                </div>

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
                                    <Show
                                        when={!versionsQuery.isLoading}
                                        fallback={<Loading />}
                                    >
                                        <Show
                                            when={!versionsQuery.isError}
                                            fallback={
                                                <ErrorBox
                                                    error={versionsQuery.error}
                                                />
                                            }
                                        >
                                            <Show
                                                when={
                                                    versionsQuery.data &&
                                                    versionsQuery.data.data
                                                        .length > 0
                                                        ? versionsQuery.data
                                                        : undefined
                                                }
                                                fallback={
                                                    <EmptyState
                                                        title="No versions yet"
                                                        message="Ingest a CycloneDX SBOM for this artifact to see it here."
                                                    />
                                                }
                                            >
                                                {(d) => (
                                                    <VersionsTab
                                                        versions={d().data}
                                                        pagination={
                                                            d().pagination
                                                        }
                                                        onPageChange={
                                                            setVersionOffset
                                                        }
                                                    />
                                                )}
                                            </Show>
                                        </Show>
                                    </Show>
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
                                                when={
                                                    changelogQuery.data &&
                                                    changelogQuery.data.entries
                                                        .length > 0
                                                        ? changelogQuery.data
                                                        : undefined
                                                }
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
                                                    />
                                                )}
                                            </Show>
                                        </Show>
                                    </Show>
                                </Show>

                                <Show when={tab() === "licenses"}>
                                    <Show
                                        when={!licenseQuery.isLoading}
                                        fallback={<Loading />}
                                    >
                                        <Show
                                            when={!licenseQuery.isError}
                                            fallback={
                                                <ErrorBox
                                                    error={licenseQuery.error}
                                                />
                                            }
                                        >
                                            <Show
                                                when={
                                                    licenseQuery.data &&
                                                    licenseQuery.data.licenses
                                                        .length > 0
                                                        ? licenseQuery.data
                                                        : undefined
                                                }
                                                fallback={
                                                    <EmptyState
                                                        title="No license data"
                                                        message="No license information found for this artifact's latest SBOM."
                                                    />
                                                }
                                            >
                                                {(d) => (
                                                    <LicensesTab
                                                        licenses={d().licenses}
                                                    />
                                                )}
                                            </Show>
                                        </Show>
                                    </Show>
                                </Show>
                            </>
                        )}
                    </Show>
                </Show>
            </Show>
        </>
    );
}
