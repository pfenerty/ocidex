import { createSignal } from "solid-js";
import { DEFAULT_PAGE_SIZE } from "~/api/client";
import { A, useSearchParams } from "@solidjs/router";
import { useLicenses } from "~/api/queries";
import type { components } from "~/types/openapi";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { SpdxBadgeCell, LicenseCategoryCell } from "~/components/cells";
import { Button, PageHeader, TabBar, Toolbar } from "~/components/ui";
import type { ToolbarField } from "~/components/ui";

type LicenseCount = components["schemas"]["LicenseCount"];

const categoryTabs = [
    { value: "", label: "All" },
    { value: "permissive", label: "Permissive" },
    { value: "copyleft", label: "Copyleft" },
    { value: "weak-copyleft", label: "Weak Copyleft" },
    { value: "uncategorized", label: "Uncategorized" },
] as const;

const FILTERS: ToolbarField[] = [
    { kind: "text", key: "name", placeholder: "Filter by name…", label: "Filter by name" },
    { kind: "text", key: "spdx", placeholder: "Filter by SPDX ID…", label: "Filter by SPDX ID" },
];

export default function Licenses() {
    const [offset, setOffset] = createSignal(0);
    const limit = DEFAULT_PAGE_SIZE;

    // All three filters live in the URL now. The two text boxes already
    // re-queried on every keystroke — the "Search" button only ever reset the
    // offset — so this adds the 300ms pause the requests were missing and makes
    // a filtered list something you can link to or reload back into.
    const [searchParams, setSearchParams] = useSearchParams();
    const param = (key: string): string => {
        const v = searchParams[key];
        return (Array.isArray(v) ? v[0] : v) ?? "";
    };

    const query = useLicenses(() => ({
        name: param("name") !== "" ? param("name") : undefined,
        spdx_id: param("spdx") !== "" ? param("spdx") : undefined,
        category: param("category") !== "" ? param("category") : undefined,
        limit,
        offset: offset(),
    }));

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
                <Button as={A} href={`/licenses/${l.id}/components`} size="sm">
                    View
                </Button>
            ),
        },
    ];

    return (
        <>
            <PageHeader title="Licenses" subtitle="All licenses found across ingested SBOMs" />

            {/* This strip highlighted correctly on its own, but carried the same
                stray `tab-btn` class as the two that did not. <TabBar> is the
                only writer of the `.tab-bar button.active` contract. */}
            <TabBar
                variant="filter"
                label="License category"
                tabs={categoryTabs.map((t) => ({ id: t.value, label: t.label }))}
                active={param("category")}
                onSelect={(value) => {
                    // "All" is the empty tab id. Passed as undefined rather
                    // than "" so the removal is stated in the router's own
                    // vocabulary instead of relying on it to coerce an empty
                    // string — either way the param must be absent, since
                    // absence is the single representation of "not filtering"
                    // that <Toolbar> already follows for its own fields.
                    setSearchParams({ category: value === "" ? undefined : value });
                    setOffset(0);
                }}
                class="mb-4"
            />

            {/* Any committed filter is a new result set, so page 1 is the only
                honest place to land. */}
            <Toolbar class="mb-4" fields={FILTERS} onChange={() => setOffset(0)} />

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
