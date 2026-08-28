import { Show, For } from "solid-js";
import { A } from "@solidjs/router";
import DataTable from "~/components/DataTable";
import type { Column, SortDir } from "~/components/DataTable";
import { SeverityPill, VulnId } from "~/components/cells";
import { StatusPill } from "~/components/ui/Badge";
import { TabBar } from "~/components/ui";
import { VulnSummaryBar } from "~/components/VulnBadge";
import type { SBOMVulnEntry, VulnSummary } from "~/api/client";
import { useSBOMVulns } from "~/api/queries";
import type { SBOMVulnSortKey } from "~/api/queries";
import type { VulnSeverityFilter } from "~/api/queries";
import { componentHref } from "./componentHref";
import "./VulnerabilitiesTab.css";

const SEVERITY_TABS = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

const SORT_KEYS: SBOMVulnSortKey[] = [
    "severity",
    "cvss_score",
    "affected_package_count",
    "canonical_id",
];

const SEVERITIES: VulnSeverityFilter[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

/**
 * AffectedPackagesList expands one finding into the packages it lands on.
 *
 * The rows come inline on the vulnerability, not from a second request, because
 * the server already has to gather them to count them — so unlike the cluster
 * page's workload list there is nothing to gate on `when`.
 */
function AffectedPackagesList(props: { vuln: SBOMVulnEntry; when: boolean }) {
    return (
        <Show when={props.when}>
            <ul class="affected-packages">
                <For each={props.vuln.affectedPackages}>
                    {(p) => (
                        <li>
                            <A href={componentHref(p.name, p.group, p.version)}>{p.name}</A>
                            <Show when={p.version}>
                                <span class="text-muted font-mono text-sm"> @ {p.version}</span>
                            </Show>
                            <Show when={p.fixedVersion}>
                                {(fixed) => (
                                    <span class="text-sm"> · fixed in <span class="font-mono">{fixed()}</span></span>
                                )}
                            </Show>
                            {/* An inherited match is a weaker claim than a direct
                                one — the advisory was published against the source
                                package, not this binary — so it is labelled rather
                                than folded in silently. */}
                            <Show when={p.matchedViaSource}>
                                <span class="ml-2">
                                    <StatusPill
                                        variant="default"
                                        title="Matched via the component's source package, not its own purl"
                                    >
                                        via source
                                    </StatusPill>
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
 * VulnerabilitiesTab is where the SBOM band's vulnerability tile now leads.
 * Before it existed the tile rendered as a bare <div> among five <button>s —
 * it looked like a control and did nothing, because the page had nowhere to
 * send the reader.
 *
 * Rows are keyed by canonical id server-side, so an advisory published under
 * several ids appears once with the package count of the whole alias group.
 * That is the same keying GetSBOMVulnSummary uses, which is what keeps this
 * list and the tile above it telling the same story.
 *
 * Severity filter, sort and page live in search params, so "the criticals in
 * this image, worst first" is a link.
 */
export function VulnerabilitiesTab(props: {
    sbomId: string;
    summary: VulnSummary | undefined;
    severity: VulnSeverityFilter | undefined;
    sortBy: SBOMVulnSortKey;
    sortDir: SortDir;
    offset: number;
    expanded: { has: (key: string) => boolean; toggle: (key: string) => void };
    onSeverityChange: (severity: string | undefined) => void;
    onSort: (sortKey: string, dir: SortDir) => void;
    onPageChange: (offset: number) => void;
}) {
    const query = useSBOMVulns(
        () => props.sbomId,
        () => ({
            ...(props.severity === undefined ? {} : { severity: props.severity }),
            sort: props.sortBy,
            dir: props.sortDir,
            limit: 50,
            offset: props.offset,
        }),
    );

    const rowKey = (v: SBOMVulnEntry) => v.canonicalId || v.id;

    const columns: Column<SBOMVulnEntry>[] = [
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
            // A count on its own is not actionable: "3 packages" only helps once
            // you know which three, so it expands rather than just reporting.
            header: "Affected packages",
            sortKey: "affected_package_count",
            sortType: "numeric",
            render: (v) => (
                <>
                    <button
                        type="button"
                        class="link-button"
                        aria-expanded={props.expanded.has(rowKey(v))}
                        onClick={() => props.expanded.toggle(rowKey(v))}
                    >
                        {v.affectedPackageCount.toLocaleString()}{" "}
                        {v.affectedPackageCount === 1 ? "package" : "packages"}
                    </button>
                    <AffectedPackagesList vuln={v} when={props.expanded.has(rowKey(v))} />
                </>
            ),
        },
        {
            header: "Summary",
            render: (v) => <span class="text-sm">{v.summary ?? "—"}</span>,
        },
    ];

    return (
        <>
            {/* The severity breakdown used to sit above the tabs, duplicating
                the tile. It belongs here, where it heads the list it describes. */}
            <VulnSummaryBar summary={props.summary} />

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
                    props.summary === undefined
                        ? "Not scanned"
                        : "No known vulnerabilities"
                }
                emptyMessage={
                    props.summary === undefined
                        ? "This SBOM has not been matched against the vulnerability store yet. That is unknown exposure, not zero."
                        : "No advisory in the vulnerability store matches a package in this SBOM. That is a statement about what is known today, not a guarantee."
                }
            />
        </>
    );
}

export { SEVERITIES, SORT_KEYS };
