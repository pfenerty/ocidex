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
    /** The SBOM the counts come from: the artifact's most recently ingested. */
    sbomId?: string;
    subjectVersion?: string;
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
                {/* Which build this is. Unsaid, the table read as "every
                    license in this artifact's history" (ocidex-nps9.29). */}
                <Show when={props.sbomId}>
                    {(id) => (
                        <p class="text-muted text-sm mb-4">
                            From the most recently ingested SBOM
                            <Show when={props.subjectVersion}>
                                {(v) => <>, <span class="font-mono">{v()}</span></>}
                            </Show>
                            . <A href={`/sboms/${id()}`}>View that SBOM</A>
                        </p>
                    )}
                </Show>

                {/* A note, not an alarm: GPL in a Debian base image is normal,
                    and a red error banner read as a failure. */}
                <Show when={hasCopyleft()}>
                    <div class="alert alert-info mb-4">
                        Includes copyleft licenses. Check their terms if you
                        redistribute this artifact.
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
                                {CATEGORY_COLORS[cat]?.label ?? cat} ({plural(count ?? 0, "component")})
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
