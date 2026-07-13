import { createSignal, Show, For } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { useTopVulnerabilities } from "~/api/queries";
import type { components } from "~/types/openapi";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { SeverityPill, VulnId } from "~/components/cells";

type TopVulnEntry = components["schemas"]["TopVulnEntry"];

const SEVERITY_TABS = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] as const;
const limit = 50;

export default function Vulnerabilities() {
    const navigate = useNavigate();
    const [offset, setOffset] = createSignal(0);
    const [severityFilter, setSeverityFilter] = createSignal("");
    const [idQuery, setIdQuery] = createSignal("");

    const query = useTopVulnerabilities(() => ({
        limit,
        offset: offset(),
        severity: severityFilter(),
    }));

    const handleTabChange = (tab: string) => {
        setSeverityFilter(tab === "All" ? "" : tab);
        setOffset(0);
    };

    const submitIdSearch = (e: Event) => {
        e.preventDefault();
        const q = idQuery().trim();
        if (q) navigate(`/vulnerabilities/${encodeURIComponent(q)}`);
    };

    const formatDate = (iso: string | undefined) =>
        iso ? new Date(iso).toLocaleDateString() : "—";

    const columns: Column<TopVulnEntry>[] = [
        {
            header: "Vulnerability",
            render: (row) => (
                <VulnId canonicalId={row.canonicalId} nativeId={row.id} />
            ),
        },
        {
            header: "Severity",
            render: (row) => (
                <SeverityPill severity={row.severity}>
                    {row.severity}
                </SeverityPill>
            ),
        },
        {
            header: "CVSS",
            align: "right",
            render: (row) =>
                row.cvssScore !== undefined ? row.cvssScore.toFixed(1) : "—",
        },
        {
            header: "Summary",
            render: (row) => (
                <span class="text-muted">{row.summary ?? "—"}</span>
            ),
        },
        {
            header: "Affected SBOMs",
            align: "right",
            render: (row) => row.affectedSbomCount.toLocaleString(),
        },
        {
            header: "Affected Packages",
            align: "right",
            render: (row) => row.affectedPurlCount.toLocaleString(),
        },
        {
            header: "Published",
            render: (row) => (
                <span class="text-muted">{formatDate(row.publishedAt)}</span>
            ),
        },
    ];

    return (
        <>
            <div class="page-header">
                <div class="page-header-row">
                    <div>
                        <h2>Vulnerabilities</h2>
                        <p>
                            Most-found CVEs across all tracked artifacts
                            <Show when={query.data}>
                                {(d) => (
                                    <span class="text-muted">
                                        {" "}
                                        &mdash;{" "}
                                        {d().pagination.total.toLocaleString()}{" "}
                                        total
                                    </span>
                                )}
                            </Show>
                        </p>
                    </div>
                </div>

                <div class="tab-bar">
                    <For each={SEVERITY_TABS}>
                        {(tab) => (
                            <button
                                class={`tab-btn${(tab === "All" ? "" : tab) === severityFilter() ? " tab-active" : ""}`}
                                onClick={() => handleTabChange(tab)}
                            >
                                {tab}
                            </button>
                        )}
                    </For>
                </div>

                <form class="search-bar mb-4" onSubmit={submitIdSearch}>
                    <input
                        type="text"
                        placeholder="Jump to CVE / GHSA / OSV id…"
                        value={idQuery()}
                        onInput={(e) => setIdQuery(e.currentTarget.value)}
                    />
                    <button type="submit" class="btn-primary">
                        Go
                    </button>
                </form>
            </div>

            <DataTable
                columns={columns}
                rows={query.data?.data ?? undefined}
                loading={query.isFetching}
                isError={query.isError}
                error={query.error}
                emptyTitle="No vulnerabilities found."
                pagination={
                    query.data
                        ? { pagination: query.data.pagination, onPageChange: setOffset }
                        : undefined
                }
            />
        </>
    );
}
