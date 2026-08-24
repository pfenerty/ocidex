import { Show } from "solid-js";
import { A } from "@solidjs/router";
import CopyDigest from "~/components/CopyDigest";
import { CardHeader, createExpandedSet } from "~/components/ui";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { relativeDate, formatDateTime, plural } from "~/utils/format";
import type { ArtifactGroup } from "./grouping";

type SbomEntry = ArtifactGroup["entries"][number];

/**
 * One flat row list rather than a nested render, because DataTable emits rows
 * and not a tree. The discriminant is what lets the two shapes — the artifact
 * that toggles and the SBOMs it reveals — share three columns.
 */
type Row = { kind: "artifact"; ag: ArtifactGroup } | { kind: "sbom"; entry: SbomEntry };

/**
 * ArtifactUsageTable lists the artifacts containing the selected version, each
 * expanding to the individual SBOMs it was seen in.
 */
export function ArtifactUsageTable(props: { groups: ArtifactGroup[] }) {
    const expanded = createExpandedSet();

    const rows = (): Row[] =>
        props.groups.flatMap((ag): Row[] => [
            { kind: "artifact", ag },
            ...(expanded.has(ag.key)
                ? ag.entries.map((entry): Row => ({ kind: "sbom", entry }))
                : []),
        ]);

    const columns: Column<Row>[] = [
        {
            header: "",
            class: "row-expander",
            render: (row) =>
                row.kind === "artifact" ? (expanded.has(row.ag.key) ? "▼" : "▶") : null,
        },
        {
            header: "Artifact",
            render: (row) =>
                row.kind === "artifact" ? (
                    <Show
                        when={row.ag.artifactId}
                        fallback={<span>{row.ag.artifactName ?? row.ag.key.slice(0, 8)}</span>}
                        keyed
                    >
                        {(artifactId) => (
                            <A href={`/artifacts/${artifactId}`} onClick={(e) => e.stopPropagation()}>
                                {row.ag.artifactName ?? artifactId.slice(0, 8)}
                            </A>
                        )}
                    </Show>
                ) : (
                    <>
                        <A href={`/sboms/${row.entry.sbomId}`}>
                            {row.entry.subjectVersion ?? formatDateTime(row.entry.sbomCreatedAt)}
                        </A>
                        <Show when={row.entry.architecture} keyed>
                            {(arch) => <span class="badge badge-primary ml-2">{arch}</span>}
                        </Show>
                        <Show when={row.entry.sbomDigest} keyed>
                            {(digest) => (
                                <span class="ml-3">
                                    <CopyDigest
                                        digest={digest}
                                        artifactName={row.entry.artifactName ?? undefined}
                                    />
                                </span>
                            )}
                        </Show>
                    </>
                ),
        },
        {
            header: "SBOMs",
            class: "text-muted whitespace-nowrap",
            render: (row) =>
                row.kind === "artifact" ? (
                    plural(row.ag.entries.length, "SBOM")
                ) : (
                    <span title={new Date(row.entry.sbomCreatedAt).toLocaleString()}>
                        {relativeDate(row.entry.sbomCreatedAt)}
                    </span>
                ),
        },
    ];

    return (
        <DataTable
            caption={<CardHeader title="Artifacts" count={props.groups.length} />}
            columns={columns}
            rows={rows()}
            loading={false}
            isError={false}
            emptyTitle="No artifacts"
            emptyMessage="This version was not seen in any artifact."
            rowClass={(row) => (row.kind === "sbom" ? "row-child" : undefined)}
            rowClickable={(row) => row.kind === "artifact"}
            onRowClick={(row) => {
                if (row.kind === "artifact") expanded.toggle(row.ag.key);
            }}
        />
    );
}
