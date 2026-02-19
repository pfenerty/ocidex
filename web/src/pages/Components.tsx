import { createSignal } from "solid-js";
import { Show, For } from "solid-js";
import { A } from "@solidjs/router";
import { useDistinctComponents, useComponentPurlTypes } from "~/api/queries";
import { Loading, ErrorBox, EmptyState } from "~/components/Feedback";
import Pagination from "~/components/Pagination";

type SortColumn = "name" | "version_count" | "sbom_count";
type SortDir = "asc" | "desc";

export default function Components() {
    const [offset, setOffset] = createSignal(0);
    const [nameFilter, setNameFilter] = createSignal("");
    const [groupFilter, setGroupFilter] = createSignal("");
    const [purlTypeFilter, setPurlTypeFilter] = createSignal("");
    const [sortBy, setSortBy] = createSignal<SortColumn>("name");
    const [sortDir, setSortDir] = createSignal<SortDir>("asc");
    const limit = 50;

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

    const toggleSort = (col: SortColumn) => {
        if (sortBy() === col) {
            setSortDir((d) => (d === "asc" ? "desc" : "asc"));
        } else {
            setSortBy(col);
            setSortDir(col === "name" ? "asc" : "desc");
        }
        setOffset(0);
    };

    const sortArrow = (col: SortColumn) => {
        if (sortBy() !== col) return null;
        return (
            <span class="sort-arrow">
                {sortDir() === "asc" ? "\u25B2" : "\u25BC"}
            </span>
        );
    };

    const overviewHref = (c: { name: string; group?: string }) => {
        const params = new URLSearchParams({ name: c.name });
        if (c.group) params.set("group", c.group);
        return `/components/overview?${params.toString()}`;
    };

    const formatCount = (n: number) => n.toLocaleString();

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

            <div class="search-bar mb-md">
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
                <Show when={nameFilter() || groupFilter() || purlTypeFilter()}>
                    <button type="button" onClick={handleClear}>
                        Clear
                    </button>
                </Show>
            </div>

            <Show when={!query.isLoading} fallback={<Loading />}>
                <Show
                    when={!query.isError}
                    fallback={<ErrorBox error={query.error} />}
                >
                    <Show
                        when={query.data && query.data.data.length > 0}
                        fallback={
                            <EmptyState
                                title="No components found"
                                message={
                                    nameFilter() || purlTypeFilter()
                                        ? "No libraries matching your filters were found."
                                        : "No libraries have been ingested yet."
                                }
                            />
                        }
                    >
                        <div class="card">
                            <div class="table-wrapper">
                                <table>
                                    <thead>
                                        <tr>
                                            <th
                                                class="th-sortable"
                                                onClick={() =>
                                                    toggleSort("name")
                                                }
                                            >
                                                Component{sortArrow("name")}
                                            </th>
                                            <th
                                                class="th-sortable text-right"
                                                onClick={() =>
                                                    toggleSort("version_count")
                                                }
                                            >
                                                Versions
                                                {sortArrow("version_count")}
                                            </th>
                                            <th
                                                class="th-sortable text-right"
                                                onClick={() =>
                                                    toggleSort("sbom_count")
                                                }
                                            >
                                                Found In
                                                {sortArrow("sbom_count")}
                                            </th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <For each={query.data!.data}>
                                            {(component) => (
                                                <tr>
                                                    <td>
                                                        <A
                                                            href={overviewHref(
                                                                component,
                                                            )}
                                                        >
                                                            <Show
                                                                when={
                                                                    component.group
                                                                }
                                                            >
                                                                <span class="text-muted">
                                                                    {
                                                                        component.group
                                                                    }
                                                                    /
                                                                </span>
                                                            </Show>
                                                            <strong>
                                                                {component.name}
                                                            </strong>
                                                        </A>
                                                        <For
                                                            each={
                                                                component.purlTypes
                                                            }
                                                        >
                                                            {(pt) => (
                                                                <>
                                                                    {" "}
                                                                    <span class="badge-sm">
                                                                        {pt}
                                                                    </span>
                                                                </>
                                                            )}
                                                        </For>
                                                    </td>
                                                    <td class="text-right">
                                                        {formatCount(
                                                            component.versionCount,
                                                        )}
                                                    </td>
                                                    <td class="text-right">
                                                        {formatCount(
                                                            component.sbomCount,
                                                        )}
                                                    </td>
                                                </tr>
                                            )}
                                        </For>
                                    </tbody>
                                </table>
                            </div>
                            <Pagination
                                pagination={query.data!.pagination}
                                onPageChange={setOffset}
                            />
                        </div>
                    </Show>
                </Show>
            </Show>
        </>
    );
}
