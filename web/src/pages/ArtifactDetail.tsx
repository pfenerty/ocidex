import { createSignal, Show, For } from "solid-js";
import { A, useParams } from "@solidjs/router";
import {
    useArtifact,
    useArtifactSBOMs,
    useArtifactChangelog,
    useArtifactLicenseSummary,
} from "~/api/queries";
import type {
    SBOMSummary,
    SBOMRef,
    ChangeSummary,
    ComponentDiff,
    LicenseCount,
    PaginationMeta,
} from "~/api/client";
import { Loading, ErrorBox, EmptyState } from "~/components/Feedback";
import Pagination from "~/components/Pagination";
import PurlLink from "~/components/PurlLink";
import { purlToRegistryUrl, purlTypeLabel } from "~/utils/purl";
import {
    artifactDisplayName,
    sbomShortLabel,
    formatDateTime,
    relativeDate,
    shortDigest,
    plural,
} from "~/utils/format";
import { containerRegistryUrl, detectRegistry } from "~/utils/oci";

export default function ArtifactDetail() {
    const params = useParams<{ id: string }>();
    const [sbomOffset, setSbomOffset] = createSignal(0);
    const [tab, setTab] = createSignal<"sboms" | "changelog" | "licenses">(
        "sboms",
    );
    const sbomLimit = 25;

    const artifactQuery = useArtifact(() => params.id);

    const sbomsQuery = useArtifactSBOMs(
        () => params.id,
        () => ({ limit: sbomLimit, offset: sbomOffset() }),
    );

    const changelogQuery = useArtifactChangelog(() => params.id, {
        enabled: () => tab() === "changelog",
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
                    {(() => {
                        const a = artifactQuery.data!;
                        return (
                            <>
                                <div class="page-header">
                                    <div class="page-header-row">
                                        <div>
                                            <h2>
                                                <Show
                                                    when={
                                                        a.type ===
                                                            "container" &&
                                                        detectRegistry(
                                                            a.name,
                                                        ) !== "redhat"
                                                    }
                                                    fallback={artifactDisplayName(
                                                        a,
                                                    )}
                                                >
                                                    <a
                                                        href={containerRegistryUrl(
                                                            a.name,
                                                        )}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                    >
                                                        {artifactDisplayName(a)}
                                                    </a>
                                                </Show>
                                            </h2>
                                            <p class="text-muted">
                                                <span class="badge">
                                                    {a.type}
                                                </span>{" "}
                                                {plural(a.sbomCount, "SBOM")}
                                                {" · First tracked "}
                                                {relativeDate(a.createdAt)}
                                            </p>
                                        </div>
                                        <div class="btn-group">
                                            <Show
                                                when={
                                                    a.purl &&
                                                    purlToRegistryUrl(a.purl!)
                                                }
                                            >
                                                <a
                                                    href={
                                                        purlToRegistryUrl(
                                                            a.purl!,
                                                        )!
                                                    }
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    class="btn btn-sm btn-primary"
                                                >
                                                    View on{" "}
                                                    {purlTypeLabel(a.purl!) ??
                                                        "Registry"}
                                                </a>
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
                                                {a.name}
                                            </span>
                                        </div>
                                        <div class="detail-field">
                                            <span class="detail-label">
                                                Type
                                            </span>
                                            <span class="detail-value">
                                                {a.type}
                                            </span>
                                        </div>
                                        <Show when={a.group}>
                                            <div class="detail-field">
                                                <span class="detail-label">
                                                    Group
                                                </span>
                                                <span class="detail-value">
                                                    {a.group}
                                                </span>
                                            </div>
                                        </Show>
                                        <Show when={a.purl}>
                                            <div class="detail-field">
                                                <span class="detail-label">
                                                    Package URL
                                                </span>
                                                <span class="detail-value">
                                                    <PurlLink
                                                        purl={a.purl!}
                                                        showBadge
                                                    />
                                                </span>
                                            </div>
                                        </Show>
                                        <Show when={a.cpe}>
                                            <div class="detail-field">
                                                <span class="detail-label">
                                                    CPE
                                                </span>
                                                <span class="detail-value mono text-sm">
                                                    {a.cpe}
                                                </span>
                                            </div>
                                        </Show>
                                        <div class="detail-field">
                                            <span class="detail-label">
                                                First Tracked
                                            </span>
                                            <span class="detail-value">
                                                {formatDateTime(a.createdAt)}
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
                                            {a.id}
                                        </p>
                                    </details>
                                </div>

                                <div class="tab-bar">
                                    <button
                                        class={
                                            tab() === "sboms" ? "active" : ""
                                        }
                                        onClick={() => setTab("sboms")}
                                    >
                                        SBOMs ({a.sbomCount})
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

                                <Show when={tab() === "sboms"}>
                                    <Show
                                        when={!sbomsQuery.isLoading}
                                        fallback={<Loading />}
                                    >
                                        <Show
                                            when={!sbomsQuery.isError}
                                            fallback={
                                                <ErrorBox
                                                    error={sbomsQuery.error}
                                                />
                                            }
                                        >
                                            <Show
                                                when={
                                                    sbomsQuery.data &&
                                                    sbomsQuery.data.data
                                                        .length > 0
                                                }
                                                fallback={
                                                    <EmptyState
                                                        title="No SBOMs yet"
                                                        message="Ingest a CycloneDX SBOM for this artifact to see it here."
                                                    />
                                                }
                                            >
                                                <SBOMsTab
                                                    sboms={
                                                        sbomsQuery.data!.data
                                                    }
                                                    pagination={
                                                        sbomsQuery.data!
                                                            .pagination
                                                    }
                                                    artifactName={a.name}
                                                    artifactType={a.type}
                                                    onPageChange={setSbomOffset}
                                                />
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
                                                }
                                                fallback={
                                                    <EmptyState
                                                        title="No changes detected"
                                                        message="At least two SBOMs are needed to generate a changelog. Ingest another SBOM for this artifact to see what changed."
                                                    />
                                                }
                                            >
                                                <ChangelogTab
                                                    entries={
                                                        changelogQuery.data!
                                                            .entries
                                                    }
                                                />
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
                                                }
                                                fallback={
                                                    <EmptyState
                                                        title="No license data"
                                                        message="No license information found for this artifact's latest SBOM."
                                                    />
                                                }
                                            >
                                                <LicensesTab
                                                    licenses={
                                                        licenseQuery.data!
                                                            .licenses
                                                    }
                                                />
                                            </Show>
                                        </Show>
                                    </Show>
                                </Show>
                            </>
                        );
                    })()}
                </Show>
            </Show>
        </>
    );
}

function CopyDigest(props: {
    digest: string;
    artifactName: string;
    isContainer: boolean;
}) {
    const [copied, setCopied] = createSignal(false);

    const ref = () =>
        props.isContainer
            ? `${props.artifactName}@${props.digest}`
            : props.digest;

    const copy = async () => {
        try {
            await navigator.clipboard.writeText(ref());
        } catch {
            // Fallback for non-HTTPS contexts
            const ta = document.createElement("textarea");
            ta.value = ref();
            ta.style.position = "fixed";
            ta.style.opacity = "0";
            document.body.appendChild(ta);
            ta.select();
            document.execCommand("copy");
            document.body.removeChild(ta);
        }
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
    };

    return (
        <button
            type="button"
            class="copy-btn mono text-sm"
            title={`Click to copy: ${ref()}`}
            onClick={copy}
        >
            {copied() ? "Copied!" : shortDigest(props.digest)}
        </button>
    );
}

function SBOMsTab(props: {
    sboms: SBOMSummary[];
    pagination: PaginationMeta;
    artifactName: string;
    artifactType: string;
    onPageChange: (offset: number) => void;
}) {
    return (
        <div class="card">
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>Version</th>
                            <th>Components</th>
                            <th>Digest</th>
                            <th>Build Date</th>
                        </tr>
                    </thead>
                    <tbody>
                        <For each={props.sboms}>
                            {(sbom) => (
                                <tr>
                                    <td>
                                        <A href={`/sboms/${sbom.id}`}>
                                            {sbomShortLabel(sbom)}
                                        </A>
                                    </td>
                                    <td>
                                        <Show
                                            when={sbom.componentCount != null}
                                            fallback={
                                                <span class="text-muted">
                                                    —
                                                </span>
                                            }
                                        >
                                            {plural(
                                                sbom.componentCount!,
                                                "component",
                                            )}
                                        </Show>
                                    </td>
                                    <td>
                                        <Show
                                            when={sbom.digest}
                                            fallback={
                                                <span class="text-muted">
                                                    —
                                                </span>
                                            }
                                        >
                                            <CopyDigest
                                                digest={sbom.digest!}
                                                artifactName={
                                                    props.artifactName
                                                }
                                                isContainer={
                                                    props.artifactType ===
                                                    "container"
                                                }
                                            />
                                        </Show>
                                    </td>
                                    <td
                                        class="nowrap text-muted"
                                        title={new Date(
                                            sbom.buildDate ?? sbom.createdAt,
                                        ).toLocaleString()}
                                    >
                                        {relativeDate(
                                            sbom.buildDate ?? sbom.createdAt,
                                        )}
                                    </td>
                                </tr>
                            )}
                        </For>
                    </tbody>
                </table>
            </div>
            <Pagination
                pagination={props.pagination}
                onPageChange={props.onPageChange}
            />
        </div>
    );
}

const categoryColors: Record<string, { bg: string; label: string }> = {
    permissive: { bg: "var(--color-success)", label: "Permissive" },
    "weak-copyleft": { bg: "var(--color-warning)", label: "Weak Copyleft" },
    copyleft: { bg: "var(--color-danger)", label: "Copyleft" },
    unknown: { bg: "var(--color-text-dim)", label: "Unknown" },
};

function LicensesTab(props: { licenses: LicenseCount[] }) {
    const total = () =>
        props.licenses.reduce(
            (acc: number, l: LicenseCount) => acc + l.componentCount,
            0,
        );
    const byCat = () =>
        props.licenses.reduce(
            (acc: Record<string, number>, l: LicenseCount) => {
                acc[l.category] = (acc[l.category] || 0) + l.componentCount;
                return acc;
            },
            {} as Record<string, number>,
        );
    const hasCopyleft = () => (byCat()["copyleft"] || 0) > 0;

    return (
        <>
            <Show when={hasCopyleft()}>
                <div class="alert alert-danger mb-md">
                    <strong>Copyleft licenses detected.</strong> Review the
                    licenses below for compliance requirements.
                </div>
            </Show>

            <div class="license-bar mb-md">
                <For each={Object.entries(byCat())}>
                    {([cat, count]) => (
                        <div
                            class="license-bar-segment"
                            style={{
                                width: `${((count as number) / total()) * 100}%`,
                                background: categoryColors[cat]?.bg ?? "gray",
                            }}
                            title={`${categoryColors[cat]?.label ?? cat}: ${plural(count as number, "component")}`}
                        />
                    )}
                </For>
            </div>

            <div class="license-legend mb-md">
                <For each={Object.entries(byCat())}>
                    {([cat, count]) => (
                        <span class="license-legend-item">
                            <span
                                class="license-dot"
                                style={{
                                    background:
                                        categoryColors[cat]?.bg ?? "gray",
                                }}
                            />
                            {categoryColors[cat]?.label ?? cat} (
                            {count as number})
                        </span>
                    )}
                </For>
            </div>

            <div class="card">
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>License</th>
                                <th>SPDX ID</th>
                                <th>Category</th>
                                <th>Components</th>
                            </tr>
                        </thead>
                        <tbody>
                            <For each={props.licenses}>
                                {(lic) => (
                                    <tr>
                                        <td>
                                            <A
                                                href={`/licenses/${lic.id}/components`}
                                            >
                                                {lic.name}
                                            </A>
                                        </td>
                                        <td>
                                            <Show
                                                when={lic.spdxId}
                                                fallback={
                                                    <span class="text-muted">
                                                        —
                                                    </span>
                                                }
                                            >
                                                <span class="badge badge-primary">
                                                    {lic.spdxId}
                                                </span>
                                            </Show>
                                        </td>
                                        <td>
                                            <span
                                                class={`badge ${
                                                    lic.category === "copyleft"
                                                        ? "badge-danger"
                                                        : lic.category ===
                                                            "weak-copyleft"
                                                          ? "badge-warning"
                                                          : lic.category ===
                                                              "permissive"
                                                            ? "badge-success"
                                                            : ""
                                                }`}
                                            >
                                                {categoryColors[lic.category]
                                                    ?.label ?? lic.category}
                                            </span>
                                        </td>
                                        <td>{lic.componentCount}</td>
                                    </tr>
                                )}
                            </For>
                        </tbody>
                    </table>
                </div>
            </div>
        </>
    );
}

function changelogRefLabel(ref: {
    id: string;
    subjectVersion?: string;
    createdAt: string;
    buildDate?: string;
}): string {
    if (ref.subjectVersion) return ref.subjectVersion;
    return relativeDate(ref.buildDate ?? ref.createdAt);
}

interface ChangelogEntryData {
    from: SBOMRef;
    to: SBOMRef;
    summary: ChangeSummary;
    changes: ComponentDiff[];
}

function ChangelogTab(props: { entries: ChangelogEntryData[] }) {
    return (
        <For each={props.entries}>
            {(entry) => (
                <div class="changelog-entry">
                    <div class="changelog-entry-header">
                        <div class="text-sm">
                            <A href={`/sboms/${entry.from.id}`} class="mono">
                                {changelogRefLabel(entry.from)}
                            </A>
                            {" → "}
                            <A href={`/sboms/${entry.to.id}`} class="mono">
                                {changelogRefLabel(entry.to)}
                            </A>
                            <span class="text-muted">
                                {" "}
                                (
                                {relativeDate(
                                    entry.to.buildDate ?? entry.to.createdAt,
                                )}
                                )
                            </span>
                        </div>
                        <div class="changelog-summary">
                            <Show when={entry.summary.added > 0}>
                                <span class="badge badge-success">
                                    +{entry.summary.added} added
                                </span>
                            </Show>
                            <Show when={entry.summary.removed > 0}>
                                <span class="badge badge-danger">
                                    -{entry.summary.removed} removed
                                </span>
                            </Show>
                            <Show when={entry.summary.modified > 0}>
                                <span class="badge badge-warning">
                                    ~{entry.summary.modified} modified
                                </span>
                            </Show>
                        </div>
                    </div>
                    <div class="table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>Change</th>
                                    <th>Component</th>
                                    <th>Version</th>
                                    <th>Package</th>
                                </tr>
                            </thead>
                            <tbody>
                                <For each={entry.changes}>
                                    {(change) => (
                                        <tr>
                                            <td>
                                                <span
                                                    class={`badge ${
                                                        change.type === "added"
                                                            ? "badge-success"
                                                            : change.type ===
                                                                "removed"
                                                              ? "badge-danger"
                                                              : "badge-warning"
                                                    }`}
                                                >
                                                    {change.type}
                                                </span>
                                            </td>
                                            <td>
                                                {change.group
                                                    ? `${change.group}/`
                                                    : ""}
                                                {change.name}
                                            </td>
                                            <td class="mono">
                                                <Show
                                                    when={
                                                        change.previousVersion
                                                    }
                                                >
                                                    <span class="text-muted">
                                                        {change.previousVersion}
                                                    </span>
                                                    {" → "}
                                                </Show>
                                                {change.version ?? "—"}
                                            </td>
                                            <td class="mono truncate text-muted">
                                                {change.purl ?? "—"}
                                            </td>
                                        </tr>
                                    )}
                                </For>
                            </tbody>
                        </table>
                    </div>
                </div>
            )}
        </For>
    );
}
