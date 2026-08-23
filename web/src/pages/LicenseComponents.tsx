import { createSignal, Show } from "solid-js";
import { DEFAULT_PAGE_SIZE } from "~/api/client";
import { A, useParams } from "@solidjs/router";
import { useLicenses, useLicenseComponents } from "~/api/queries";
import type { components } from "~/types/openapi";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { ComponentNameCell, TypeBadge, VersionCell, PurlLink } from "~/components/cells";
import { Skeleton, SkeletonHeader } from "~/components/Skeleton";
import { PageHeader, QueryBoundary } from "~/components/ui";

type ComponentSummary = components["schemas"]["ComponentSummary"];

export default function LicenseComponents() {
    const params = useParams<{ id: string }>();
    const [offset, setOffset] = createSignal(0);
    const limit = DEFAULT_PAGE_SIZE;

    const licenseQuery = useLicenses(() => ({ limit: 200 }));

    const licenseName = () => {
        const match = licenseQuery.data?.data.find((l) => l.id === params.id);
        return match?.name ?? params.id;
    };

    const licenseSpdx = () => {
        const match = licenseQuery.data?.data.find((l) => l.id === params.id);
        return match?.spdxId;
    };

    const query = useLicenseComponents(
        () => params.id,
        () => ({ limit, offset: offset() }),
    );

    const columns: Column<ComponentSummary>[] = [
        {
            header: "Component",
            render: (c) => (
                <ComponentNameCell
                    name={c.name}
                    group={c.group}
                    href={`/components/${c.id}`}
                />
            ),
        },
        {
            header: "Type",
            render: (c) => <TypeBadge type={c.type} />,
        },
        {
            header: "Version",
            render: (c) => <VersionCell version={c.version} />,
        },
        {
            header: "Package",
            render: (c) =>
                c.purl !== undefined ? (
                    <PurlLink purl={c.purl} showBadge />
                ) : (
                    <span class="text-muted">—</span>
                ),
        },
        {
            header: "Found In",
            render: (c) => (
                <A href={`/sboms/${c.sbomId}`} class="text-sm">
                    View SBOM →
                </A>
            ),
        },
    ];

    return (
        <>
            <div class="breadcrumb">
                <A href="/licenses">Licenses</A>
                <span class="separator">/</span>
                <span>
                    {licenseQuery.isLoading ? (
                        <Skeleton width="6rem" inline />
                    ) : (
                        licenseName()
                    )}
                </span>
                <span class="separator">/</span>
                <span>Components</span>
            </div>

            <QueryBoundary query={licenseQuery} loading={<SkeletonHeader />}>
                {() => (
                <PageHeader
                    title={licenseName()}
                    subtitle={
                        <>
                            <Show when={licenseSpdx()}>
                                <span class="badge badge-primary">
                                    {licenseSpdx()}
                                </span>{" "}
                            </Show>
                            Components using this license
                        </>
                    }
                />
                )}
            </QueryBoundary>

            <DataTable
                columns={columns}
                rows={query.data?.data ?? undefined}
                loading={query.isFetching}
                isError={query.isError}
                error={query.error}
                emptyTitle="No components"
                emptyMessage="No components are associated with this license."
                pagination={
                    query.data
                        ? { pagination: query.data.pagination, onPageChange: setOffset }
                        : undefined
                }
            />
        </>
    );
}
