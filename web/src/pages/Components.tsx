import "./Components.css";
import { DEFAULT_PAGE_SIZE } from "~/api/client";
import { createSignal } from "solid-js";
import { Show, For } from "solid-js";
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
import { Button } from "~/components/ui";

type DistinctComponentSummary = components["schemas"]["DistinctComponentSummary"];
type ComponentSummary = components["schemas"]["ComponentSummary"];
type SortColumn = "name" | "version_count" | "sbom_count";

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
            <div class="page-header">
                <div class="page-header-row">
                    <div>
                        <h2>Component occurrences</h2>
                        <p>
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
                        </p>
                    </div>
                    <Button as={A} href="/components" size="sm">
                        All components
                    </Button>
                </div>
            </div>

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
    const [nameFilter, setNameFilter] = createSignal("");
    const [groupFilter, setGroupFilter] = createSignal("");
    const [purlTypeFilter, setPurlTypeFilter] = createSignal("");
    const [sortBy, setSortBy] = createSignal<SortColumn>("sbom_count");
    const [sortDir, setSortDir] = createSignal<SortDir>("desc");
    const limit = DEFAULT_PAGE_SIZE;

    const purlTypesQuery = useComponentPurlTypes();

    const query = useDistinctComponents(() => ({
        name: nameFilter(),
        group: groupFilter(),
        type: "library",
        purl_type: purlTypeFilter(),
        sort: sortBy(),
        sort_dir: sortDir(),
        limit,
        offset: offset(),
    }));

    const handleClear = () => {
        setNameFilter("");
        setGroupFilter("");
        setPurlTypeFilter("");
        setOffset(0);
    };

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
        {
            header: "Versions",
            sortKey: "version_count",
            sortType: "numeric",
            align: "right",
            render: (c) => formatCount(c.versionCount),
        },
        {
            header: "Found In",
            sortKey: "sbom_count",
            sortType: "numeric",
            align: "right",
            render: (c) => formatCount(c.sbomCount),
        },
    ];

    return (
        <>
            <div class="page-header">
                <div class="page-header-row">
                    <div>
                        <h2>Components</h2>
                        <p>
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
                        </p>
                    </div>
                </div>
            </div>

            <div class="search-bar mb-4">
                <input
                    type="text"
                    placeholder="Filter by name…"
                    value={nameFilter()}
                    onInput={(e) => {
                        setNameFilter(e.currentTarget.value);
                        setOffset(0);
                    }}
                />
                <input
                    type="text"
                    placeholder="Group…"
                    value={groupFilter()}
                    onInput={(e) => {
                        setGroupFilter(e.currentTarget.value);
                        setOffset(0);
                    }}
                />
                <select
                    value={purlTypeFilter()}
                    onChange={(e) => {
                        setPurlTypeFilter(e.currentTarget.value);
                        setOffset(0);
                    }}
                >
                    <option value="">All types</option>
                    <For each={purlTypesQuery.data?.types}>
                        {(t) => <option value={t}>{t}</option>}
                    </For>
                </select>
                <Show when={nameFilter() !== "" || groupFilter() !== "" || purlTypeFilter() !== ""}>
                    <Button type="button" size="sm" onClick={handleClear}>
                        Clear
                    </Button>
                </Show>
            </div>

            <DataTable
                columns={columns}
                rows={query.data?.data ?? undefined}
                loading={query.isFetching}
                isError={query.isError}
                error={query.error}
                emptyTitle="No components found"
                emptyMessage={
                    nameFilter() !== "" || purlTypeFilter() !== ""
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
