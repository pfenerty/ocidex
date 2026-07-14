import { Show, For } from "solid-js";
import "./LicensesTab.css";
import { A } from "@solidjs/router";
import type { LicenseCount } from "~/api/client";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { SpdxBadgeCell, LicenseCategoryCell } from "~/components/cells";
import { plural } from "~/utils/format";
import { CATEGORY_COLORS } from "~/utils/licenseUtils";

export function LicensesTab(props: {
    licenses: LicenseCount[] | undefined;
    loading: boolean;
    isError: boolean;
    error?: unknown;
}) {
    const licenses = () => props.licenses ?? [];
    const total = () =>
        licenses().reduce((acc: number, l: LicenseCount) => acc + l.componentCount, 0);
    const byCat = () =>
        licenses().reduce(
            (acc: Partial<Record<string, number>>, l: LicenseCount) => {
                acc[l.category] = (acc[l.category] ?? 0) + l.componentCount;
                return acc;
            },
            {} as Partial<Record<string, number>>,
        );
    const hasCopyleft = () => (byCat().copyleft ?? 0) > 0;

    const sortedLicenses = () =>
        props.licenses
            ? [...props.licenses].sort((a, b) => b.componentCount - a.componentCount)
            : undefined;

    const columns: Column<LicenseCount>[] = [
        {
            header: "License",
            render: (lic) => (
                <A href={`/licenses/${lic.id}/components`}>{lic.name}</A>
            ),
        },
        {
            header: "SPDX ID",
            render: (lic) => <SpdxBadgeCell spdxId={lic.spdxId} />,
        },
        {
            header: "Category",
            render: (lic) => <LicenseCategoryCell category={lic.category} />,
        },
        {
            header: "Components",
            render: (lic) => lic.componentCount,
        },
    ];

    return (
        <>
            <Show when={licenses().length > 0}>
                <Show when={hasCopyleft()}>
                    <div class="alert alert-danger mb-4">
                        <strong>Copyleft licenses detected.</strong> Review the
                        licenses below for compliance requirements.
                    </div>
                </Show>

                <div class="license-bar mb-4">
                    <For each={Object.entries(byCat())}>
                        {([cat, count]) => (
                            <div
                                class="license-bar-segment"
                                style={{
                                    width:
                                        count !== undefined
                                            ? `${(count / total()) * 100}%`
                                            : "0%",
                                    background: CATEGORY_COLORS[cat]?.bg ?? "gray",
                                }}
                                title={`${CATEGORY_COLORS[cat]?.label ?? cat}: ${count !== undefined ? plural(count, "component") : ""}`}
                            />
                        )}
                    </For>
                </div>

                <div class="license-legend mb-4">
                    <For each={Object.entries(byCat())}>
                        {([cat, count]) => (
                            <span class="license-legend-item">
                                <span
                                    class="license-dot"
                                    style={{
                                        background:
                                            CATEGORY_COLORS[cat]?.bg ?? "gray",
                                    }}
                                />
                                {CATEGORY_COLORS[cat]?.label ?? cat} ({count})
                            </span>
                        )}
                    </For>
                </div>
            </Show>

            <DataTable
                columns={columns}
                rows={sortedLicenses()}
                loading={props.loading}
                isError={props.isError}
                error={props.error}
                emptyTitle="No license data"
                emptyMessage="No license information found for this artifact's latest SBOM."
            />
        </>
    );
}
