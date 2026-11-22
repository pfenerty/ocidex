import { clusterNames, runningForVersion, type RunningWorkload } from "./RunningTab";
import { Show, For } from "solid-js";
import { A } from "@solidjs/router";
import type { ArtifactVersionSummary, PaginationMeta } from "~/api/client";
import DataTable from "~/components/DataTable";
import type { Column, SortDir } from "~/components/DataTable";
import { SigningBadge, TimestampCell } from "~/components/cells";
import { VulnCountBadges } from "~/components/VulnBadge";
import { Button, ExternalAnchor, StatusPill } from "~/components/ui";
import { StatusChip } from "~/components/ui";
import { VULN_DATA_STATUS } from "~/utils/status";
import { buildTime } from "~/utils/format";
import { formatDelta, UNTAGGED_VERSION, versionDeltas, type VersionDelta } from "~/utils/versionDelta";
import { severityPoints } from "./ArtifactChange";

function DeltaCell(props: { delta: VersionDelta; value: number | undefined }) {
    return (
        <Show
            when={props.value !== undefined}
            fallback={
                <span
                    class="text-muted"
                    title={props.delta.noSharedArch === true ? "no shared architecture with the previous version" : undefined}
                >
                    —
                </span>
            }
        >
            <span
                class="delta-cell"
                classList={{ "delta-zero": props.value === 0, "delta-worse": (props.value ?? 0) > 0 }}
            >
                {formatDelta(props.value ?? 0)}
            </span>
        </Show>
    );
}

export function VersionsTab(props: {
    /** Where the artifact runs, for the Running column (ocidex-70eo.8);
     * undefined for a signed-out reader, who gets no column. */
    running?: RunningWorkload[];
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
            header: "Arch",
            // A count, with the list on hover: seven chips a row was most of
            // the table's ink and said less than the number.
            render: (version) => (
                <Show
                    when={version.architectures && version.architectures.length > 0}
                    fallback={<span class="text-muted">—</span>}
                >
                    <span class="font-mono text-sm text-muted" title={(version.architectures ?? []).join(", ")}>
                        {version.architectures?.length === 1
                            ? version.architectures[0]
                            : `${version.architectures?.length ?? 0} arch`}
                    </span>
                </Show>
            ),
        },
    ];

    // A signing status every row shares is said once, by the band's Signing
    // tile; a column repeating it on every row is noise.
    const signingVaries = () => new Set((props.versions ?? []).map((v) => v.signingStatus)).size > 1;
    const signingColumn: Column<ArtifactVersionSummary> = {
        header: "Signing",
        render: (version) => <SigningBadge status={version.signingStatus} />,
    };

    // Deltas compare each row with the one below it, which is only the
    // previous version in the default order. Sorted by severity, the row below
    // is just the next-worst, so the columns are dropped.
    const deltas = () => versionDeltas(severityPoints(props.versions));
    // A row the table renders is always in props.versions; the empty fallback
    // only keeps a lookup miss from throwing.
    const deltaFor = (version: ArtifactVersionSummary): VersionDelta => {
        const i = (props.versions ?? []).indexOf(version);
        return i < 0 ? {} : deltas()[i];
    };
    const deltaColumns = (): Column<ArtifactVersionSummary>[] =>
        props.sortBy !== undefined
            ? []
            : [
                  {
                      header: "Δ crit",
                      align: "right",
                      render: (version) => {
                          const d = deltaFor(version);
                          return <DeltaCell delta={d} value={d.critical} />;
                      },
                  },
                  {
                      header: "Δ high",
                      align: "right",
                      render: (version) => {
                          const d = deltaFor(version);
                          return <DeltaCell delta={d} value={d.high} />;
                      },
                  },
              ];

    const columns = (): Column<ArtifactVersionSummary>[] => [
        {
            header: "Version",
            render: (version) => (
                <A href={`/sboms/${version.sbomId}`} class="font-mono">
                    {version.versionKey}
                </A>
            ),
        },
        ...deltaColumns(),
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
                                <ExternalAnchor url={url()}>
                                    <code title={rev()}>{rev().slice(0, 7)}</code>
                                </ExternalAnchor>
                            )}
                        </Show>
                    )}
                </Show>
            ),
        },
        {
            header: "Build Date",
            render: (version) => (
                <TimestampCell iso={buildTime(version)} />
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
                        <StatusChip
                            status={version.vulnMatched ? VULN_DATA_STATUS.clean : VULN_DATA_STATUS.unscanned}
                        />
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
        ...(props.isContainer && signingVaries() ? [signingColumn] : []),
        ...(props.running !== undefined
            ? [
                  {
                      header: "Running",
                      render: (version: ArtifactVersionSummary) => {
                          const names = clusterNames(
                              runningForVersion(props.running ?? [], version.sbomId, version.versionKey),
                          );
                          return (
                              <Show when={names.length > 0} fallback={<span class="text-muted">—</span>}>
                                  <span class="flex flex-wrap gap-1">
                                      <For each={names}>
                                          {(n) => <StatusPill variant="success">{n}</StatusPill>}
                                      </For>
                                  </span>
                              </Show>
                          );
                      },
                  },
              ]
            : []),
        {
            header: "",
            // One SBOM per architecture is still one build, so the history
            // page had nothing to compare. The button appears only when some
            // architecture was built more than once, rather than as a
            // disabled button that styled every other row differently
            // (ocidex-nps9.23).
            render: (version) => (
                // The build history page looks a version up by name, and the
                // untagged row has none.
                <Show
                    when={
                        version.versionKey !== UNTAGGED_VERSION &&
                        version.sbomCount > Math.max(1, version.architectures?.length ?? 0)
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
