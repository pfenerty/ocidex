import { Show } from "solid-js";
import { A } from "@solidjs/router";
import DataTable from "~/components/DataTable";
import type { Column, SortDir } from "~/components/DataTable";
import { SeverityPill } from "~/components/VulnBadge";
import { VulnId } from "~/components/cells";
import { createExpandedSet, TabBar } from "~/components/ui";
import { plural } from "~/utils/format";
import type { RunningVuln, WorkloadCoverage } from "~/api/client";
import { useClusterVulns } from "~/api/queries";
import type { ClusterVulnSortKey, VulnSeverityFilter } from "~/api/queries";
import { RunningWorkloadsList } from "./RunningWorkloads";

const SEVERITY_TABS = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

const SORT_KEYS: ClusterVulnSortKey[] = [
    "severity",
    "cvss_score",
    "workload_count",
    "canonical_id",
];

const SEVERITIES: VulnSeverityFilter[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

/**
 * VulnerabilitiesTab lists what the cluster is actually running, not what the
 * catalog knows about. Rows are keyed by canonical id server-side, so an
 * advisory published under several ids appears once with the workload count of
 * the whole alias group.
 *
 * Severity filter, sort and page all live in search params, so "the criticals
 * running in prod, worst first" is a link rather than a sequence of clicks to
 * describe.
 */
export function VulnerabilitiesTab(props: {
    clusterId: string;
    coverage: WorkloadCoverage;
    severity: VulnSeverityFilter | undefined;
    sortBy: ClusterVulnSortKey;
    sortDir: SortDir;
    offset: number;
    onSeverityChange: (severity: string | undefined) => void;
    onSort: (sortKey: string, dir: SortDir) => void;
    onPageChange: (offset: number) => void;
}) {
    const expanded = createExpandedSet();
    const query = useClusterVulns(
        () => props.clusterId,
        () => ({
            ...(props.severity === undefined ? {} : { severity: props.severity }),
            sort: props.sortBy,
            dir: props.sortDir,
            limit: 50,
            offset: props.offset,
        }),
    );
    const notAssessed = () => props.coverage.unknown + props.coverage.unresolvable;

    const columns: Column<RunningVuln>[] = [
        {
            header: "ID",
            sortKey: "canonical_id",
            render: (v) => <VulnId canonicalId={v.canonical_id} nativeId={v.id} />,
        },
        {
            header: "Severity",
            sortKey: "severity",
            sortType: "numeric",
            render: (v) => (
                <SeverityPill severity={v.severity}>{v.severity ?? "unknown"}</SeverityPill>
            ),
        },
        {
            header: "CVSS",
            align: "right",
            sortKey: "cvss_score",
            sortType: "numeric",
            render: (v) => (
                <Show when={v.cvss_score} fallback={<span class="text-muted">—</span>}>
                    {(score) => <span class="font-mono text-sm">{score().toFixed(1)}</span>}
                </Show>
            ),
        },
        {
            // The count is a button rather than a number because the number on
            // its own is not actionable: "3 workloads" is only useful once you
            // know which three.
            header: "Running workloads",
            sortKey: "workload_count",
            sortType: "numeric",
            render: (v) => (
                <>
                    <button
                        type="button"
                        class="link-button"
                        aria-expanded={expanded.has(v.canonical_id)}
                        onClick={() => expanded.toggle(v.canonical_id)}
                    >
                        {v.workload_count.toLocaleString()}{" "}
                        {v.workload_count === 1 ? "workload" : "workloads"}
                    </button>
                    <RunningWorkloadsList
                        canonicalId={v.canonical_id}
                        clusterId={props.clusterId}
                        when={expanded.has(v.canonical_id)}
                    />
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
            <Show when={notAssessed() > 0}>
                <p class="coverage-caveat">
                    {plural(notAssessed(), "running container")} are excluded from this list:{" "}
                    {props.coverage.unknown.toLocaleString()} have no ingested SBOM and{" "}
                    {props.coverage.unresolvable.toLocaleString()} have no readable digest. Their
                    exposure is unknown, not zero.
                </p>
            </Show>

            {/* See Vulnerabilities.tsx: the hand-rolled strip emitted
                `tab-btn`/`tab-active`, which the stylesheet does not define. */}
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
                emptyTitle="Nothing known running here"
                emptyMessage="No vulnerability is known for the images this cluster runs that OCIDex could match. Check the coverage figures above before reading that as clean."
            />
            <p class="text-muted mt-2">
                <A href="/vulnerabilities">
                    Catalog-wide vulnerabilities
                </A>
            </p>
        </>
    );
}

export { SEVERITIES, SORT_KEYS };
