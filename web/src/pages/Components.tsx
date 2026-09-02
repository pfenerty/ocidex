import "./Components.css";
import { DEFAULT_PAGE_SIZE } from "~/api/client";
import { createSignal } from "solid-js";
import { Show } from "solid-js";
import { A, useSearchParams } from "@solidjs/router";
import {
    useDistinctComponents,
    useComponentPurlTypes,
    useComponentsByPurl,
} from "~/api/queries";
import type { components } from "~/types/openapi";
import DataTable from "~/components/DataTable";
import type { Column, SortDir } from "~/components/DataTable";
import { ComponentNameCell } from "~/components/cells";
import { VulnCountBadges } from "~/components/VulnBadge";
import { Button, PageHeader, Toolbar } from "~/components/ui";
import type { ToolbarField } from "~/components/ui";

type DistinctComponentSummary = components["schemas"]["DistinctComponentSummary"];
type ComponentSummary = components["schemas"]["ComponentSummary"];
type SortColumn = "name" | "version_count" | "sbom_count" | "severity";

export default function Components() {
    const [searchParams] = useSearchParams();
    const purl = () => {
        const p = searchParams.purl;
        return (Array.isArray(p) ? p[0] : p) ?? "";
    };

    return (
        <Show when={purl() === ""} fallback={<PurlOccurrences purl={purl()} />}>
            <ComponentBrowser />
        </Show>
    );
}

/**
 * Every SBOM carrying one exact purl (ADR-042 R6). A component row is
 * SBOM-scoped, so there is no component detail route to link to; this filtered
 * list is what a purl link resolves to instead.
 */
function PurlOccurrences(props: { purl: string }) {
    const [offset, setOffset] = createSignal(0);
    const limit = DEFAULT_PAGE_SIZE;

    const query = useComponentsByPurl(() => ({
        purl: props.purl,
        limit,
        offset: offset(),
    }));

    const columns: Column<ComponentSummary>[] = [
        { header: "Component", render: (c) => c.name },
        { header: "Version", render: (c) => c.version ?? "—" },
        { header: "Type", render: (c) => c.type },
        {
            header: "SBOM",
            render: (c) => <A href={`/sboms/${c.sbomId}`}>View SBOM</A>,
        },
    ];

    return (
        <>
            <PageHeader
                title="Component occurrences"
                subtitle={
                    <>
                        <span class="font-mono text-sm">{props.purl}</span>
                        <Show when={query.data}>
                            {(d) => (
                                <span class="text-muted">
                                    {" "}
                                    &mdash; found in{" "}
                                    {d().pagination.total.toLocaleString()} SBOMs
                                </span>
                            )}
                        </Show>
                    </>
                }
                actions={
                    <Button as={A} href="/components" size="sm">
                        All components
                    </Button>
                }
            />

            <DataTable
                columns={columns}
                rows={query.data?.data ?? undefined}
                loading={query.isFetching}
                isError={query.isError}
                error={query.error}
                emptyTitle="No occurrences found"
                emptyMessage="No visible SBOM contains this package URL."
                pagination={
                    query.data ? { pagination: query.data.pagination, onPageChange: setOffset } : undefined
                }
            />
        </>
    );
}

function ComponentBrowser() {
    const [offset, setOffset] = createSignal(0);
    const [sortBy, setSortBy] = createSignal<SortColumn>("sbom_count");
    const [sortDir, setSortDir] = createSignal<SortDir>("desc");
    const limit = DEFAULT_PAGE_SIZE;

    // The three filters were undebounced local signals: a request per keystroke
    // against the slowest endpoint in the app, and a filtered list nobody could
    // link to. <Toolbar> gives them the 300ms pause and puts them in the URL.
    const [searchParams] = useSearchParams();
    const param = (key: string): string => {
        const v = searchParams[key];
        return (Array.isArray(v) ? v[0] : v) ?? "";
    };

    const purlTypesQuery = useComponentPurlTypes();

    // Built once rather than in a memo: <Toolbar> renders one row per entry, so
    // a fresh array identity would remount the inputs mid-keystroke. The
    // package types arrive from a query, which is what the thunk is for.
    const filters: ToolbarField[] = [
        { kind: "text", key: "name", placeholder: "Filter by name…", label: "Filter by name" },
        { kind: "text", key: "group", placeholder: "Group…", label: "Filter by group" },
        {
            kind: "select",
            key: "purlType",
            options: () => purlTypesQuery.data?.types ?? [],
            allLabel: "All types",
            label: "Package type",
        },
    ];

    const isFiltered = () => filters.some((f) => param(f.key) !== "");

    const query = useDistinctComponents(() => ({
        name: param("name"),
        group: param("group"),
        type: "library",
        purl_type: param("purlType"),
        sort: sortBy(),
        sort_dir: sortDir(),
        limit,
        offset: offset(),
    }));

    const overviewHref = (c: { name: string; group?: string }) => {
        const params = new URLSearchParams({ name: c.name });
        if (c.group !== undefined && c.group !== "") params.set("group", c.group);
        return `/components/overview?${params.toString()}`;
    };

    const formatCount = (n: number) => n.toLocaleString();

    const columns: Column<DistinctComponentSummary>[] = [
        {
            header: "Component",
            sortKey: "name",
            sortType: "text",
            render: (c) => (
                <ComponentNameCell
                    name={c.name}
                    group={c.group}
                    purlTypes={c.purlTypes ?? undefined}
                    href={overviewHref(c)}
                />
            ),
        },
        // Every number on this row is corpus-wide, and each column said so only
        // in the page subtitle (ocidex-7gf7.7). Read from the row rather than
        // from the heading — which is how a wide table is read — "3 versions"
        // could as easily have meant three in whatever SBOM the reader came
        // from.
        {
            header: (
                <>
                    Versions
                    <span class="col-scope">all SBOMs</span>
                </>
            ),
            mobileLabel: "Versions",
            sortKey: "version_count",
            sortType: "numeric",
            align: "right",
            render: (c) => formatCount(c.versionCount),
        },
        {
            header: (
                <>
                    Found In
                    <span class="col-scope">SBOMs</span>
                </>
            ),
            mobileLabel: "Found In",
            sortKey: "sbom_count",
            sortType: "numeric",
            align: "right",
            render: (c) => formatCount(c.sbomCount),
        },
        {
            header: (
                <>
                    Vulnerabilities
                    <span
                        class="col-scope"
                        title="Known findings against any version of this package — unlike the artifact list, a zero here means nothing is known against it, not that it was never scanned"
                    >
                        all SBOMs
                    </span>
                </>
            ),
            mobileLabel: "Vulnerabilities",
            sortKey: "severity",
            sortType: "numeric",
            align: "right",
            // An em dash, not "not scanned": component_rollup has a row for
            // every package identity, so all-zero here is a real "nothing
            // known against it" rather than the /artifacts list's ambiguity
            // between no findings and never scanned (ADR-044).
            render: (c) => (
                <VulnCountBadges
                    criticalCount={c.vulns.critical}
                    highCount={c.vulns.high}
                    mediumCount={c.vulns.medium}
                    lowCount={c.vulns.low}
                    unknownCount={c.vulns.unknown}
                />
            ),
        },
    ];

    return (
        <>
            <PageHeader
                title="Components"
                subtitle={
                    <>
                        Libraries found across all SBOMs
                        <Show when={query.data}>
                            {(d) => (
                                <span class="text-muted">
                                    {" "}
                                    &mdash;{" "}
                                    {formatCount(d().pagination.total)}{" "}
                                    total
                                </span>
                            )}
                        </Show>
                    </>
                }
            />

            {/* Any committed filter is a new result set, so page 1 is the only
                honest place to land. */}
            <Toolbar class="mb-4" fields={filters} onChange={() => setOffset(0)} />

            <DataTable
                columns={columns}
                rows={query.data?.data ?? undefined}
                loading={query.isFetching}
                isError={query.isError}
                error={query.error}
                emptyTitle="No components found"
                emptyMessage={
                    isFiltered()
                        ? "No libraries matching your filters were found."
                        : "No libraries have been ingested yet."
                }
                sortBy={sortBy()}
                sortDir={sortDir()}
                onSort={(key, dir) => {
                    setSortBy(key as SortColumn);
                    setSortDir(dir);
                    setOffset(0);
                }}
                pagination={
                    query.data ? { pagination: query.data.pagination, onPageChange: setOffset } : undefined
                }
            />
        </>
    );
}
