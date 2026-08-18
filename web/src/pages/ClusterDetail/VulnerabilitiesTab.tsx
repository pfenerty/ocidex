import { Show } from "solid-js";
import { A } from "@solidjs/router";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { SeverityPill } from "~/components/VulnBadge";
import { VulnId } from "~/components/cells";
import { plural } from "~/utils/format";
import type { RunningVuln, WorkloadCoverage } from "~/api/client";
import { useClusterVulns } from "~/api/queries";

const columns: Column<RunningVuln>[] = [
    {
        header: "ID",
        render: (v) => <VulnId canonicalId={v.canonical_id} nativeId={v.id} />,
    },
    {
        header: "Severity",
        render: (v) => <SeverityPill severity={v.severity}>{v.severity ?? "unknown"}</SeverityPill>,
    },
    {
        header: "CVSS",
        align: "right",
        render: (v) => (
            <Show when={v.cvss_score} fallback={<span class="text-muted">—</span>}>
                {(score) => <span class="font-mono text-sm">{score().toFixed(1)}</span>}
            </Show>
        ),
    },
    {
        header: "Running workloads",
        align: "right",
        render: (v) => v.workload_count.toLocaleString(),
    },
    {
        header: "Summary",
        render: (v) => <span class="text-sm">{v.summary ?? "—"}</span>,
    },
];

/**
 * VulnerabilitiesTab lists what the cluster is actually running, not what the
 * catalog knows about. Rows are keyed by canonical id server-side, so an
 * advisory published under several ids appears once with the workload count of
 * the whole alias group.
 */
export function VulnerabilitiesTab(props: { clusterId: string; coverage: WorkloadCoverage }) {
    const query = useClusterVulns(() => props.clusterId, () => ({ limit: 100 }));
    const notAssessed = () => props.coverage.unknown + props.coverage.unresolvable;

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
            <DataTable
                columns={columns}
                rows={query.data?.data}
                loading={query.isLoading}
                isError={query.isError}
                error={query.error}
                emptyTitle="Nothing known running here"
                emptyMessage="No vulnerability is known for the images this cluster runs that OCIDex could match. Check the coverage figures above before reading that as clean."
            />
            <Show when={(query.data?.pagination.total ?? 0) > (query.data?.data.length ?? 0)}>
                <p class="text-muted" style={{ "margin-top": "0.5rem" }}>
                    Showing the {(query.data?.data.length ?? 0).toString()} most severe of{" "}
                    {(query.data?.pagination.total ?? 0).toLocaleString()} running here.{" "}
                    <A href="/vulnerabilities" class="dash-link">
                        Catalog-wide
                    </A>
                </p>
            </Show>
        </>
    );
}
