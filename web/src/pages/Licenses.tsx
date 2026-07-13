import { createSignal } from "solid-js";
import { For } from "solid-js";
import { A } from "@solidjs/router";
import { useLicenses } from "~/api/queries";
import type { components } from "~/types/openapi";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { SpdxBadgeCell, LicenseCategoryCell } from "~/components/cells";

type LicenseCount = components["schemas"]["LicenseCount"];

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

    const columns: Column<LicenseCount>[] = [
        {
            header: "Name",
            render: (l) => l.name,
        },
        {
            header: "SPDX ID",
            render: (l) => <SpdxBadgeCell spdxId={l.spdxId} />,
        },
        {
            header: "Category",
            render: (l) => <LicenseCategoryCell category={l.category} />,
        },
        {
            header: "Components",
            align: "right",
            render: (l) => l.componentCount.toLocaleString(),
        },
        {
            header: "",
            render: (l) => (
                <A href={`/licenses/${l.id}/components`} class="btn btn-sm">
                    View
                </A>
            ),
        },
    ];

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

            <div class="tab-bar mb-4">
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

            <form class="search-bar mb-4" onSubmit={handleSearch}>
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

            <DataTable
                columns={columns}
                rows={query.data?.data ?? undefined}
                loading={query.isFetching}
                isError={query.isError}
                error={query.error}
                emptyTitle="No licenses found"
                emptyMessage="Ingest SBOMs with license data to populate this view."
                pagination={
                    query.data
                        ? { pagination: query.data.pagination, onPageChange: setOffset }
                        : undefined
                }
            />
        </>
    );
}
