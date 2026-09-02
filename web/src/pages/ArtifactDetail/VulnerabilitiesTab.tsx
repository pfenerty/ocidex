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
 * AffectedVersionsList names the versions one finding reaches.
 *
 * This is the half of the answer the artifact page could not give before:
 * /vulnerabilities/:id sends a reader here saying "this artifact is affected",
 * and until now the page could not say which of its versions, or point at the
 * SBOM that proves it. Each row links to that version's own SBOM.
 *
 * The versions arrive inline on the finding, so the first INLINE_AFFECTED are
 * shown without asking and only the tail is behind the toggle.
 */
function AffectedVersionsList(props: { vuln: ArtifactVulnEntry; limit: number | undefined }) {
    // affectedVersions is nullable in the generated type because Go's
    // array_agg column is; no versions and an empty list mean the same thing.
    const shown = () => {
        const all = props.vuln.affectedVersions ?? [];
        return props.limit === undefined ? all : all.slice(0, props.limit);
    };
    return (
        <Show when={shown().length > 0} fallback={<span class="text-muted">—</span>}>
            <ul class="affected-versions">
                <For each={shown()}>
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
 * INLINE_AFFECTED is how many affected versions are shown without asking, the
 * same figure the SBOM tab uses for packages: enough to see the shape of what
 * a finding reaches without turning a page of findings into a wall.
 */
const INLINE_AFFECTED = 3;

/**
 * VulnerabilitiesTab is where the artifact band's vulnerability tile now leads.
 * Before it existed the tile rendered as a bare <div> among the band's buttons
 * and the page had no vulnerabilities tab at all — so the trail from
 * /vulnerabilities/:id's "Affected artifacts" ended here at a page that could
 * not name a single affected version.
 *
 * Scope note, surfaced in the header rather than left implicit: this list spans
 * the newest SBOM *per version*, while the tile above counts the latest version
 * only (ocidex-7gf7.7). The two totals therefore differ whenever an older
 * version carries something the latest one does not — which is exactly the case
 * worth showing, and exactly the case a single-version scope would hide.
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

    /**
     * scopeNote states how much of the artifact's history this list covers.
     *
     * The server caps the scan at the most recent versions (ocidex-7gf7.5) —
     * uncapped it walked every version of the artifact and timed out. A cap the
     * reader cannot see is worse than the timeout it replaced: it turns "clean
     * in the last 20 releases" into an unqualified "clean". So the cap and the
     * artifact's true version count are both named, and when nothing is left
     * out the sentence says that too rather than going quiet.
     */
    const scopeNote = () => {
        const data = query.data;
        // Both figures come from the server, and a server that predates the cap
        // sends neither — during a rolling deploy the web tier is ahead of the
        // API for a few minutes. Reading them without checking turned that into
        // a TypeError inside a reactive render, which left the tab frozen on its
        // loading skeleton for good. Unknown scope falls back to the sentence
        // that is true either way.
        const scope = data?.versionScope;
        const total = data?.totalVersions;
        if (scope === undefined || total === undefined) {
            return "Across the newest SBOM of each version.";
        }
        if (total <= scope) {
            return `Across the newest SBOM of each of this artifact's ${total.toLocaleString()} ${total === 1 ? "version" : "versions"}.`;
        }
        return `Across the newest SBOM of each of the ${scope.toLocaleString()} most recent versions, of ${total.toLocaleString()} in all.`;
    };

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
            // you know which three — so the versions themselves are the cell,
            // each linking to the SBOM that carries it.
            header: "Affected versions",
            sortKey: "affected_version_count",
            sortType: "numeric",
            render: (v) => (
                <>
                    <AffectedVersionsList
                        vuln={v}
                        limit={props.expanded.has(rowKey(v)) ? undefined : INLINE_AFFECTED}
                    />
                    <Show when={(v.affectedVersions?.length ?? 0) > INLINE_AFFECTED}>
                        <button
                            type="button"
                            class="link-button affected-more"
                            aria-expanded={props.expanded.has(rowKey(v))}
                            onClick={() => props.expanded.toggle(rowKey(v))}
                        >
                            {props.expanded.has(rowKey(v))
                                ? "Show fewer"
                                : `+${((v.affectedVersions?.length ?? 0) - INLINE_AFFECTED).toLocaleString()} more`}
                        </button>
                    </Show>
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
                {scopeNote()} The Vulnerabilities tile above counts the latest
                version only, so a finding that only an older release carries
                appears here and not there.
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
                        ? "No version in scope carries a package this advisory affects. Older versions outside the scope above, and other advisories, may still — clear the filter to see them."
                        : props.summary === undefined
                          ? "No SBOM for this artifact has been matched against the vulnerability store yet. That is unknown exposure, not zero."
                          : "No advisory in the vulnerability store matches a package in any version in scope. That is a statement about what is known today, over the versions named above, not a guarantee."
                }
            />
        </>
    );
}

export { SEVERITIES, SORT_KEYS };
