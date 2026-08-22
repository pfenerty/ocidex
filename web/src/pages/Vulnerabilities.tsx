import { createSignal, Show } from "solid-js";
import { DEFAULT_PAGE_SIZE } from "~/api/client";
import { useNavigate } from "@solidjs/router";
import { useTopVulnerabilities } from "~/api/queries";
import type { TopVulnSort } from "~/api/queries/vulns";
import type { components } from "~/types/openapi";
import DataTable from "~/components/DataTable";
import type { Column, SortDir } from "~/components/DataTable";
import { SeverityPill, VulnId } from "~/components/cells";
import { Button, TabBar } from "~/components/ui";

type TopVulnEntry = components["schemas"]["TopVulnEntry"];

const SEVERITY_TABS = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] as const;
type SeverityTab = (typeof SEVERITY_TABS)[number];
const limit = DEFAULT_PAGE_SIZE;

export default function Vulnerabilities() {
    const navigate = useNavigate();
    const [offset, setOffset] = createSignal(0);
    const [severityFilter, setSeverityFilter] = createSignal("");
    const [idQuery, setIdQuery] = createSignal("");
    const [sortBy, setSortBy] = createSignal<TopVulnSort>("severity");
    const [sortDir, setSortDir] = createSignal<SortDir>("desc");

    // The list is server-paginated, so sorting has to re-query: reordering the
    // 25 visible rows would claim a ranking the other pages don't share.
    const query = useTopVulnerabilities(() => ({
        limit,
        offset: offset(),
        severity: severityFilter(),
        sort: sortBy(),
        sort_dir: sortDir(),
    }));

    // The query wants "" for no filter; the strip wants a tab id. "All" is the
    // one value where those two representations differ.
    const activeSeverityTab = (): SeverityTab =>
        (severityFilter() === "" ? "All" : severityFilter()) as SeverityTab;
    const handleTabChange = (tab: SeverityTab) => {
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
            sortKey: "canonical_id",
            sortType: "text",
            render: (row) => (
                <VulnId canonicalId={row.canonicalId} nativeId={row.id} />
            ),
        },
        {
            header: "Severity",
            sortKey: "severity",
            sortType: "numeric",
            render: (row) => (
                <SeverityPill severity={row.severity}>
                    {row.severity}
                </SeverityPill>
            ),
        },
        {
            header: "CVSS",
            align: "right",
            sortKey: "cvss_score",
            sortType: "numeric",
            render: (row) =>
                row.cvssScore !== undefined ? row.cvssScore.toFixed(1) : "—",
        },
        {
            // Free text with no useful ordering — left unsortable deliberately.
            header: "Summary",
            render: (row) => (
                <span class="text-muted">{row.summary ?? "—"}</span>
            ),
        },
        {
            header: "Affected SBOMs",
            align: "right",
            sortKey: "affected_sbom_count",
            sortType: "numeric",
            render: (row) => row.affectedSbomCount.toLocaleString(),
        },
        {
            header: "Affected Packages",
            align: "right",
            sortKey: "affected_purl_count",
            sortType: "numeric",
            render: (row) => row.affectedPurlCount.toLocaleString(),
        },
        {
            header: "Published",
            sortKey: "published_at",
            sortType: "numeric",
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

                {/* The severity strip is <TabBar>, not hand-rolled markup: the
                    hand-rolled version emitted `tab-btn`/`tab-active`, neither
                    of which exists in the stylesheet, so the active severity
                    was indistinguishable from the other five (ocidex-ag4q.6).
                    The real contract is `.tab-bar button.active`, and TabBar is
                    the one place that writes it. */}
                <TabBar
                    tabs={SEVERITY_TABS.map((t) => ({ id: t, label: t }))}
                    active={activeSeverityTab()}
                    onSelect={handleTabChange}
                />

                <form class="search-bar mb-4" onSubmit={submitIdSearch}>
                    <input
                        type="text"
                        placeholder="Jump to CVE / GHSA / OSV id…"
                        value={idQuery()}
                        onInput={(e) => setIdQuery(e.currentTarget.value)}
                    />
                    <Button type="submit" variant="primary">
                        Go
                    </Button>
                </form>
            </div>

            <DataTable
                columns={columns}
                rows={query.data?.data ?? undefined}
                loading={query.isFetching}
                isError={query.isError}
                error={query.error}
                emptyTitle="No vulnerabilities found."
                sortBy={sortBy()}
                sortDir={sortDir()}
                onSort={(key, dir) => {
                    setSortBy(key as TopVulnSort);
                    setSortDir(dir);
                    setOffset(0);
                }}
                pagination={
                    query.data
                        ? { pagination: query.data.pagination, onPageChange: setOffset }
                        : undefined
                }
            />
        </>
    );
}
