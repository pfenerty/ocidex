import { Show, For } from "solid-js";
import { A } from "@solidjs/router";
import type { ArtifactVersionSummary, PaginationMeta } from "~/api/client";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { SigningBadge, TimestampCell } from "~/components/cells";

export function VersionsTab(props: {
    artifactId: string;
    versions: ArtifactVersionSummary[] | undefined;
    pagination: PaginationMeta | undefined;
    loading: boolean;
    isError: boolean;
    error?: unknown;
    onPageChange: (offset: number) => void;
}) {
    const columns: Column<ArtifactVersionSummary>[] = [
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
        {
            header: "",
            render: (version) => (
                <Show
                    when={version.sbomCount > 1}
                    fallback={
                        <button
                            class="btn btn-sm"
                            disabled
                            title="Only one build — need at least two to show history"
                        >
                            Build History
                        </button>
                    }
                >
                    <A
                        href={`/artifacts/${props.artifactId}/versions/${encodeURIComponent(version.versionKey)}`}
                        class="btn btn-sm"
                    >
                        Build History
                    </A>
                </Show>
            ),
        },
    ];

    return (
        <DataTable
            columns={columns}
            rows={props.versions}
            loading={props.loading}
            isError={props.isError}
            error={props.error}
            emptyTitle="No versions yet"
            emptyMessage="Ingest a CycloneDX SBOM for this artifact to see it here."
            pagination={
                props.pagination
                    ? { pagination: props.pagination, onPageChange: props.onPageChange }
                    : undefined
            }
        />
    );
}
