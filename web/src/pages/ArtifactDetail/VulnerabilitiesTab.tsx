import { Show, For } from "solid-js";
import { A } from "@solidjs/router";
import DataTable from "~/components/DataTable";
import type { Column, SortDir } from "~/components/DataTable";
import { SeverityPill, VulnId } from "~/components/cells";
import { TabBar } from "~/components/ui";
import { VulnSummaryBar } from "~/components/VulnBadge";
import type { ArtifactVulnEntry, VulnSummary } from "~/api/client";
import { useArtifactVulns } from "~/api/queries";
import type { ArtifactVulnSortKey, VulnSeverityFilter } from "~/api/queries";
import "./VulnerabilitiesTab.css";

const SEVERITY_TABS = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

const SORT_KEYS: ArtifactVulnSortKey[] = [
    "severity",
    "cvss_score",
    "affected_version_count",
    "affected_package_count",
    "canonical_id",
];

const SEVERITIES: VulnSeverityFilter[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

/**
 * AffectedVersionsList expands one finding into the versions it reaches.
 *
 * This is the half of the answer the artifact page could not give before:
 * /vulnerabilities/:id sends a reader here saying "this artifact is affected",
 * and until now the page could not say which of its versions, or point at the
 * SBOM that proves it. Each row links to that version's own SBOM.
 */
function AffectedVersionsList(props: { vuln: ArtifactVulnEntry; when: boolean }) {
    return (
        <Show when={props.when}>
            <ul class="affected-versions">
                <For each={props.vuln.affectedVersions}>
                    {(v) => (
                        <li>
                            <A href={`/sboms/${v.sbomId}?tab=vulns&vuln=${encodeURIComponent(props.vuln.canonicalId || props.vuln.id)}`}>
                                <span class="font-mono">{v.version}</span>
                            </A>
                            {/* packageNames is nullable in the generated type
                                because Go's array_agg column is; an empty list
                                just means no name to add. */}
                            <Show when={v.packageNames?.length}>
                                <span class="text-muted text-sm">
                                    {" "}· {(v.packageNames ?? []).join(", ")}
                                </span>
                            </Show>
                        </li>
                    )}
                </For>
            </ul>
        </Show>
    );
}

/**
 * VulnerabilitiesTab is where the artifact band's vulnerability tile now leads.
 * Before it existed the tile rendered as a bare <div> among the band's buttons
 * and the page had no vulnerabilities tab at all — so the trail from
 * /vulnerabilities/:id's "Affected artifacts" ended here at a page that could
 * not name a single affected version.
 *
 * Scope note, surfaced in the header rather than left implicit: this list spans
 * the newest SBOM *per version*, while the tile above counts the artifact's
 * newest SBOM only. The two totals therefore differ whenever an older version
 * carries something the newest one does not — which is exactly the case worth
 * showing, and exactly the case a single-SBOM scope would hide.
 */
export function VulnerabilitiesTab(props: {
    artifactId: string;
    summary: VulnSummary | undefined;
    severity: VulnSeverityFilter | undefined;
    /** A single advisory to pre-filter to, from ?vuln= — the reverse trail. */
    vuln: string | undefined;
    sortBy: ArtifactVulnSortKey;
    sortDir: SortDir;
    offset: number;
    expanded: { has: (key: string) => boolean; toggle: (key: string) => void };
    onSeverityChange: (severity: string | undefined) => void;
    onClearVuln: () => void;
    onSort: (sortKey: string, dir: SortDir) => void;
    onPageChange: (offset: number) => void;
}) {
    const query = useArtifactVulns(
        () => props.artifactId,
        () => ({
            ...(props.severity === undefined ? {} : { severity: props.severity }),
            ...(props.vuln === undefined ? {} : { vuln: props.vuln }),
            sort: props.sortBy,
            dir: props.sortDir,
            limit: 50,
            offset: props.offset,
        }),
    );

    const rowKey = (v: ArtifactVulnEntry) => v.canonicalId || v.id;

    const columns: Column<ArtifactVulnEntry>[] = [
        {
            header: "ID",
            sortKey: "canonical_id",
            render: (v) => <VulnId canonicalId={v.canonicalId} nativeId={v.id} />,
        },
        {
            header: "Severity",
            sortKey: "severity",
            sortType: "numeric",
            render: (v) => <SeverityPill severity={v.severity}>{v.severity}</SeverityPill>,
        },
        {
            header: "CVSS",
            align: "right",
            sortKey: "cvss_score",
            sortType: "numeric",
            render: (v) => (
                <Show when={v.cvssScore} fallback={<span class="text-muted">—</span>}>
                    {(score) => <span class="font-mono text-sm">{score().toFixed(1)}</span>}
                </Show>
            ),
        },
        {
            // The count alone is not actionable — "3 versions" only helps once
            // you know which three — so it expands into them, each linking to
            // the SBOM that carries it.
            header: "Affected versions",
            sortKey: "affected_version_count",
            sortType: "numeric",
            render: (v) => (
                <>
                    <button
                        type="button"
                        class="link-button"
                        aria-expanded={props.expanded.has(rowKey(v))}
                        onClick={() => props.expanded.toggle(rowKey(v))}
                    >
                        {v.affectedVersionCount.toLocaleString()}{" "}
                        {v.affectedVersionCount === 1 ? "version" : "versions"}
                    </button>
                    <AffectedVersionsList vuln={v} when={props.expanded.has(rowKey(v))} />
                </>
            ),
        },
        {
            header: "Packages",
            align: "right",
            sortKey: "affected_package_count",
            sortType: "numeric",
            render: (v) => <span class="font-mono text-sm">{v.affectedPackageCount.toLocaleString()}</span>,
        },
        {
            header: "Summary",
            render: (v) => <span class="text-sm">{v.summary ?? "—"}</span>,
        },
    ];

    return (
        <>
            <VulnSummaryBar summary={props.summary} />

            {/* The tile and this list count different things. Saying so is
                cheaper than the alternative reading, which is that one of them
                is broken. */}
            <p class="text-muted text-sm mb-4">
                Across the newest SBOM of each version. The Vulnerabilities tile
                above counts this artifact's newest SBOM only, so a finding fixed
                in the latest version still appears here.
            </p>

            {/* A pre-filtered list that does not say it is filtered reads as
                "this is everything", so the filter is visible and clearable. */}
            <Show when={props.vuln}>
                {(v) => (
                    <p class="mb-4 text-sm">
                        Showing <span class="font-mono">{v()}</span> only.{" "}
                        <button type="button" class="link-button" onClick={props.onClearVuln}>
                            Show all vulnerabilities
                        </button>
                    </p>
                )}
            </Show>

            <TabBar
                variant="filter"
                label="Severity"
                tabs={SEVERITY_TABS.map((t) => ({ id: t, label: t }))}
                active={props.severity ?? "All"}
                onSelect={(tab) => props.onSeverityChange(tab === "All" ? undefined : tab)}
            />

            <DataTable
                columns={columns}
                rows={query.data?.data}
                loading={query.isFetching}
                isError={query.isError}
                error={query.error}
                sortBy={props.sortBy}
                sortDir={props.sortDir}
                onSort={props.onSort}
                pagination={
                    query.data
                        ? { pagination: query.data.pagination, onPageChange: props.onPageChange }
                        : undefined
                }
                emptyTitle={
                    props.vuln !== undefined
                        ? "Not affected by this advisory"
                        : props.summary === undefined
                          ? "Not scanned"
                          : "No known vulnerabilities"
                }
                emptyMessage={
                    props.vuln !== undefined
                        ? "No version of this artifact carries a package this advisory affects. Other versions may still carry other findings — clear the filter to see them."
                        : props.summary === undefined
                          ? "No SBOM for this artifact has been matched against the vulnerability store yet. That is unknown exposure, not zero."
                          : "No advisory in the vulnerability store matches a package in any version of this artifact. That is a statement about what is known today, not a guarantee."
                }
            />
        </>
    );
}

export { SEVERITIES, SORT_KEYS };
