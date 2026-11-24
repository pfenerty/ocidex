import { createSignal, Show } from "solid-js";
import { DEFAULT_PAGE_SIZE } from "~/api/client";
import { A, useSearchParams } from "@solidjs/router";
import { useTopVulnerabilities } from "~/api/queries";
import type { TopVulnSort } from "~/api/queries/vulns";
import type { components } from "~/types/openapi";
import DataTable from "~/components/DataTable";
import type { Column, SortDir } from "~/components/DataTable";
import { SeverityPill, VulnId } from "~/components/cells";
import { PageHeader, TabBar, Toolbar } from "~/components/ui";
import { useAuth } from "~/context/auth";
import { formatDate } from "~/utils/format";
import type { ToolbarField } from "~/components/ui";

type TopVulnEntry = components["schemas"]["TopVulnEntry"];

const SEVERITY_TABS = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] as const;
type SeverityTab = (typeof SEVERITY_TABS)[number];
const limit = DEFAULT_PAGE_SIZE;

const FILTERS: ToolbarField[] = [
    {
        kind: "text",
        key: "q",
        placeholder: "Filter by CVE / GHSA / OSV id…",
        label: "Filter by vulnerability id",
    },
];

/** Whole days since `iso`, never negative. */
export function fixAgeDays(iso: string, now = Date.now()): number {
    return Math.max(0, Math.floor((now - new Date(iso).getTime()) / 86_400_000));
}

export default function Vulnerabilities() {
    const [offset, setOffset] = createSignal(0);
    // How long a fix has been out for what is still shipped: the oldest
    // unpatched exposure first.
    const [sortBy, setSortBy] = createSignal<TopVulnSort>("fixAge");
    const { user } = useAuth();
    const [sortDir, setSortDir] = createSignal<SortDir>("desc");

    // Both filters live in the URL now. The id box used to be a submit-on-Enter
    // jump that navigated away from the list entirely, which meant the one
    // question this page is for — "is this CVE anywhere in our corpus?" — could
    // only be answered by leaving the page that knows the answer.
    const [searchParams, setSearchParams] = useSearchParams();
    const param = (key: string): string => {
        const v = searchParams[key];
        return (Array.isArray(v) ? v[0] : v) ?? "";
    };
    const idQuery = () => param("q").trim();

    // The list is server-paginated, so sorting has to re-query: reordering the
    // 25 visible rows would claim a ranking the other pages don't share.
    const query = useTopVulnerabilities(() => ({
        limit,
        offset: offset(),
        q: param("q"),
        severity: param("severity"),
        sort: sortBy(),
        sortDir: sortDir(),
    }));

    // The query wants "" for no filter; the strip wants a tab id. "All" is the
    // one value where those two representations differ.
    const activeSeverityTab = (): SeverityTab => {
        const s = param("severity");
        return (s === "" ? "All" : s) as SeverityTab;
    };
    const handleTabChange = (tab: SeverityTab) => {
        // "All" leaves no severity param at all. Passed as undefined rather
        // than "" so the removal is stated in the router's own vocabulary
        // rather than relying on it to coerce an empty string; absence is the
        // single representation of "not filtering" that <Toolbar> already
        // follows for its own fields.
        setSearchParams({ severity: tab === "All" ? undefined : tab });
        setOffset(0);
    };

    const columns: Column<TopVulnEntry>[] = [
        {
            header: "Vulnerability",
            sortKey: "canonicalId",
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
            sortKey: "cvssScore",
            sortType: "numeric",
            // Mono, as the score reads on every other page (ocidex-iz0r.10).
            render: (row) =>
                row.cvssScore !== undefined ? (
                    <span class="font-mono tabular-nums">{row.cvssScore.toFixed(1)}</span>
                ) : (
                    "—"
                ),
        },
        {
            // Free text with no useful ordering — left unsortable deliberately.
            header: "Summary",
            render: (row) => (
                <span class="text-muted">{row.summary ?? "—"}</span>
            ),
        },
        {
            // Artifacts whose newest tag still carries it. "Affected SBOMs"
            // counted every SBOM ever ingested, so it only ever grew.
            header: "Latest tags still affected",
            align: "right",
            sortKey: "latestAffectedCount",
            sortType: "numeric",
            render: (row) => (
                <span
                    class="font-mono tabular-nums"
                    title={`${row.affectedSbomCount.toLocaleString()} SBOMs across every version`}
                >
                    {row.latestAffectedCount.toLocaleString()}
                </span>
            ),
        },
        {
            header: "Fix out",
            align: "right",
            sortKey: "fixAge",
            sortType: "numeric",
            render: (row) => (
                <Show when={row.latestAffectedCount > 0 ? row.fixAvailableSince : undefined} fallback={<span class="text-muted">—</span>}>
                    {(since) => (
                        <span class="font-mono tabular-nums" title={`fix available since ${formatDate(since())}`}>
                            {fixAgeDays(since())} d
                        </span>
                    )}
                </Show>
            ),
        },
        {
            header: "Affected Packages",
            align: "right",
            sortKey: "affectedPurlCount",
            sortType: "numeric",
            render: (row) => row.affectedPurlCount.toLocaleString(),
        },
        // No Published column: grype's match metadata carries no publication
        // date, so every row read "—" (ocidex-nps9.12).
    ];
    const podsColumn: Column<TopVulnEntry> = {
        header: "Running pods",
        align: "right",
        render: (row) => <span class="font-mono tabular-nums">{(row.runningPods ?? 0).toLocaleString()}</span>,
    };
    // Pods come back only for a signed-in caller; a signed-out reader gets no
    // column rather than a column of zeros.
    const visibleColumns = () => (user() !== undefined ? [...columns, podsColumn] : columns);

    return (
        <>
            <PageHeader
                title="Vulnerabilities"
                subtitle={
                    <>
                        Vulnerabilities in tracked artifacts, longest-available fix first
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
                    </>
                }
            />

            {/* The severity strip is <TabBar>, not hand-rolled markup: the
                hand-rolled version emitted `tab-btn`/`tab-active`, neither
                of which exists in the stylesheet, so the active severity
                was indistinguishable from the other five (ocidex-ag4q.6).
                The real contract is `.tab-bar button.active`, and TabBar is
                the one place that writes it.

                The strip and the search form used to sit *inside* the
                `.page-header` div, which exists only to carry the title
                block's bottom margin — so they inherited a gap of zero above
                and 1.5rem below. Lifting them out is what makes this page the
                same shape as Licenses, which had it right.

                It is a `filter` strip, not a `nav` one: it narrows the table
                below rather than changing the page (ocidex-ag4q.44). */}
            <TabBar
                variant="filter"
                label="Severity"
                tabs={SEVERITY_TABS.map((t) => ({ id: t, label: t }))}
                active={activeSeverityTab()}
                onSelect={handleTabChange}
                class="mb-4"
            />

            {/* Filters as you type, against `q` on /api/v1/vulns, which matches
                the canonical id and every alias — so a GHSA id copied out of an
                advisory finds the record the corpus files under its CVE. */}
            <Toolbar class="mb-4" fields={FILTERS} onChange={() => setOffset(0)} />

            <DataTable
                columns={visibleColumns()}
                rows={query.data?.data ?? undefined}
                loading={query.isFetching}
                isError={query.isError}
                error={query.error}
                emptyTitle={
                    idQuery() === ""
                        ? "No vulnerabilities found."
                        : `Nothing tracked here matches “${idQuery()}”.`
                }
                emptyMessage={
                    // The old jump box could reach a CVE that affects nothing we
                    // track; this list, which joins through the rollup, cannot.
                    // Offering the direct link from the empty state keeps that
                    // reach without making every reader submit a form for it.
                    <Show when={idQuery() !== ""}>
                        <>
                            It may still be a real advisory with no effect on any
                            tracked artifact.{" "}
                            <A href={`/vulnerabilities/${encodeURIComponent(idQuery())}`}>
                                Open {idQuery()} directly
                            </A>
                            .
                        </>
                    </Show>
                }
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
