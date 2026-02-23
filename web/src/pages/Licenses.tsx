import { createSignal } from "solid-js";
import { Show, For } from "solid-js";
import { A } from "@solidjs/router";
import { useLicenses } from "~/api/queries";
import { Loading, ErrorBox, EmptyState } from "~/components/Feedback";
import Pagination from "~/components/Pagination";

const categoryBadge: Record<string, string> = {
    permissive: "badge-success",
    copyleft: "badge-danger",
    "weak-copyleft": "badge-warning",
    uncategorized: "",
};

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
        name: nameFilter() || undefined,
        spdx_id: spdxFilter() || undefined,
        category: categoryFilter() || undefined,
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

            <Show when={!query.isLoading} fallback={<Loading />}>
                <Show
                    when={!query.isError}
                    fallback={<ErrorBox error={query.error} />}
                >
                    <Show
                        when={query.data && query.data.data.length > 0}
                        fallback={
                            <EmptyState
                                title="No licenses found"
                                message="Ingest SBOMs with license data to populate this view."
                            />
                        }
                    >
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
                                        <For each={query.data!.data}>
                                            {(license) => (
                                                <tr>
                                                    <td>{license.name}</td>
                                                    <td>
                                                        <Show
                                                            when={
                                                                license.spdxId
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
                                                            class={`badge ${categoryBadge[license.category] ?? ""}`}
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
