import { createSignal } from "solid-js";
import { Show, For } from "solid-js";
import { A } from "@solidjs/router";
import { useLicenses } from "~/api/queries";
import { QueryResult, EmptyState } from "~/components/Feedback";
import Pagination from "~/components/Pagination";
import { CATEGORY_COLORS } from "~/utils/licenseUtils";

const categoryTabs = [
    { value: "", label: "All" },
    { value: "permissive", label: "Permissive" },
    { value: "copyleft", label: "Copyleft" },
    { value: "weak-copyleft", label: "Weak Copyleft" },
    { value: "uncategorized", label: "Uncategorized" },
] as const;

export default function Licenses() {
    const [offset, setOffset] = createSignal(0);
    const [nameFilter, setNameFilter] = createSignal("");
    const [spdxFilter, setSpdxFilter] = createSignal("");
    const [categoryFilter, setCategoryFilter] = createSignal("");
    const limit = 50;

    const query = useLicenses(() => ({
        name: nameFilter() !== "" ? nameFilter() : undefined,
        spdx_id: spdxFilter() !== "" ? spdxFilter() : undefined,
        category: categoryFilter() !== "" ? categoryFilter() : undefined,
        limit,
        offset: offset(),
    }));

    const handleSearch = (e: Event) => {
        e.preventDefault();
        setOffset(0);
    };

    return (
        <>
            <div class="page-header">
                <div class="page-header-row">
                    <div>
                        <h2>Licenses</h2>
                        <p>All licenses found across ingested SBOMs</p>
                    </div>
                </div>
            </div>

            <div class="tab-bar mb-md">
                <For each={categoryTabs}>
                    {(tab) => (
                        <button
                            class={`tab-btn${categoryFilter() === tab.value ? " active" : ""}`}
                            onClick={() => {
                                setCategoryFilter(tab.value);
                                setOffset(0);
                            }}
                        >
                            {tab.label}
                        </button>
                    )}
                </For>
            </div>

            <form class="search-bar mb-md" onSubmit={handleSearch}>
                <input
                    type="text"
                    placeholder="Filter by name…"
                    value={nameFilter()}
                    onInput={(e) => setNameFilter(e.currentTarget.value)}
                />
                <input
                    type="text"
                    placeholder="Filter by SPDX ID…"
                    value={spdxFilter()}
                    onInput={(e) => setSpdxFilter(e.currentTarget.value)}
                />
                <button type="submit" class="btn-primary">
                    Search
                </button>
            </form>

            <QueryResult
                query={query}
                when={(d) => (d.data.length > 0 ? d : undefined)}
                empty={
                    <EmptyState
                        title="No licenses found"
                        message="Ingest SBOMs with license data to populate this view."
                    />
                }
            >
                {(d) => (
                    <div class="card">
                        <div class="table-wrapper">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Name</th>
                                        <th>SPDX ID</th>
                                        <th>Category</th>
                                        <th class="text-right">
                                            Components
                                        </th>
                                        <th />
                                    </tr>
                                </thead>
                                <tbody>
                                    <For each={d().data}>
                                        {(license) => (
                                            <tr>
                                                <td>{license.name}</td>
                                                <td>
                                                    <Show
                                                        when={
                                                            license.spdxId !== undefined
                                                        }
                                                        fallback={
                                                            <span class="text-muted">
                                                                —
                                                            </span>
                                                        }
                                                    >
                                                        <span class="badge badge-primary">
                                                            {license.spdxId}
                                                        </span>
                                                    </Show>
                                                </td>
                                                <td>
                                                    <span
                                                        class={`badge ${CATEGORY_COLORS[license.category]?.badge ?? ""}`}
                                                    >
                                                        {license.category}
                                                    </span>
                                                </td>
                                                <td class="text-right mono">
                                                    {license.componentCount}
                                                </td>
                                                <td>
                                                    <A
                                                        href={`/licenses/${license.id}/components`}
                                                        class="btn btn-sm"
                                                    >
                                                        View
                                                    </A>
                                                </td>
                                            </tr>
                                        )}
                                    </For>
                                </tbody>
                            </table>
                        </div>
                        <Pagination
                            pagination={d().pagination}
                            onPageChange={setOffset}
                        />
                    </div>
                )}
            </QueryResult>
        </>
    );
}
