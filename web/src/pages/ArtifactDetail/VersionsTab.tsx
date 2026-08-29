import { Show, For } from "solid-js";
import { A } from "@solidjs/router";
import type { ArtifactVersionSummary, PaginationMeta } from "~/api/client";
import DataTable from "~/components/DataTable";
import type { Column, SortDir } from "~/components/DataTable";
import { SigningBadge, TimestampCell } from "~/components/cells";
import { VulnCountBadges } from "~/components/VulnBadge";
import { Button } from "~/components/ui";

export function VersionsTab(props: {
    artifactId: string;
    /** Architecture and signing are OCI concepts; both columns are dropped for
     *  other artifact types rather than shown as a column of em-dashes. */
    isContainer: boolean;
    versions: ArtifactVersionSummary[] | undefined;
    pagination: PaginationMeta | undefined;
    loading: boolean;
    isError: boolean;
    error?: unknown;
    onPageChange: (offset: number) => void;
    /** Sorting is server-side: the API pages, so a client-side sort would only
     *  reorder the 25 rows currently on screen. */
    sortBy: string | undefined;
    sortDir: SortDir;
    onSort: (sortKey: string, dir: SortDir) => void;
}) {
    const imageColumns: Column<ArtifactVersionSummary>[] = [
        {
            header: "Architectures",
            render: (version) => (
                <Show
                    when={
                        version.architectures && version.architectures.length > 0
                    }
                    fallback={<span class="text-muted">—</span>}
                >
                    <For each={version.architectures ?? []}>
                        {(arch) => (
                            <span
                                class="badge badge-primary"
                                style={{ "margin-right": "4px" }}
                            >
                                {arch}
                            </span>
                        )}
                    </For>
                </Show>
            ),
        },
        {
            header: "Signing",
            render: (version) => <SigningBadge status={version.signingStatus} />,
        },
    ];

    const columns = (): Column<ArtifactVersionSummary>[] => [
        {
            header: "Version",
            render: (version) => (
                <A href={`/sboms/${version.sbomId}`}>{version.versionKey}</A>
            ),
        },
        {
            header: "Revision",
            render: (version) => (
                <Show
                    when={version.revision}
                    fallback={<span class="text-muted">—</span>}
                >
                    {(rev) => (
                        <Show
                            when={version.sourceUrl}
                            fallback={
                                <code title={rev()}>{rev().slice(0, 7)}</code>
                            }
                        >
                            {(url) => (
                                <a
                                    href={url()}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >
                                    <code title={rev()}>{rev().slice(0, 7)}</code>
                                </a>
                            )}
                        </Show>
                    )}
                </Show>
            ),
        },
        {
            header: "Build Date",
            render: (version) => (
                <TimestampCell iso={version.buildDate ?? version.createdAt} />
            ),
        },
        {
            header: "Vulnerabilities",
            sortKey: "severity",
            sortType: "numeric",
            render: (version) => (
                // `vulns` is absent when nothing is recorded for this version's
                // newest SBOM, which means "no findings" or "never scanned"
                // without distinguishing them. Rendering that as a zero — or as
                // VulnCountBadges' own em dash, which reads the same — would
                // claim a clean bill of health nobody issued (ADR-044).
                <Show
                    when={version.vulns}
                    fallback={
                        <span
                            class="text-muted"
                            title="No findings recorded for this version — it may never have been scanned"
                        >
                            not scanned
                        </span>
                    }
                >
                    {(v) => (
                        <VulnCountBadges
                            criticalCount={v().critical}
                            highCount={v().high}
                            mediumCount={v().medium}
                            lowCount={v().low}
                            unknownCount={v().unknown}
                        />
                    )}
                </Show>
            ),
        },
        ...(props.isContainer ? imageColumns : []),
        {
            header: "",
            render: (version) => (
                <Show
                    when={version.sbomCount > 1}
                    fallback={
                        <Button
                            size="sm"
                            disabled
                            title="Only one build — need at least two to show history"
                        >
                            Build History
                        </Button>
                    }
                >
                    <Button
                        as={A}
                        href={`/artifacts/${props.artifactId}/versions/${encodeURIComponent(version.versionKey)}`}
                        size="sm"
                    >
                        Build History
                    </Button>
                </Show>
            ),
        },
    ];

    return (
        <DataTable
            columns={columns()}
            rows={props.versions}
            loading={props.loading}
            isError={props.isError}
            error={props.error}
            emptyTitle="No versions yet"
            emptyMessage="Ingest a CycloneDX SBOM for this artifact to see it here."
            sortBy={props.sortBy}
            sortDir={props.sortDir}
            onSort={props.onSort}
            pagination={
                props.pagination
                    ? { pagination: props.pagination, onPageChange: props.onPageChange }
                    : undefined
            }
        />
    );
}
