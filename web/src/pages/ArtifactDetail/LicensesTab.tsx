import { Show, For } from "solid-js";
import { A } from "@solidjs/router";
import type { LicenseCount } from "~/api/client";
import { plural } from "~/utils/format";
import { CATEGORY_COLORS } from "~/utils/licenseUtils";

export function LicensesTab(props: { licenses: LicenseCount[] }) {
    const sorted = () =>
        [...props.licenses].sort((a, b) => b.componentCount - a.componentCount);
    const total = () =>
        props.licenses.reduce(
            (acc: number, l: LicenseCount) => acc + l.componentCount,
            0,
        );
    const byCat = () =>
        props.licenses.reduce(
            (acc: Partial<Record<string, number>>, l: LicenseCount) => {
                acc[l.category] = (acc[l.category] ?? 0) + l.componentCount;
                return acc;
            },
            {} as Partial<Record<string, number>>,
        );
    const hasCopyleft = () => (byCat().copyleft ?? 0) > 0;

    return (
        <>
            <Show when={hasCopyleft()}>
                <div class="alert alert-danger mb-md">
                    <strong>Copyleft licenses detected.</strong> Review the
                    licenses below for compliance requirements.
                </div>
            </Show>

            <div class="license-bar mb-md">
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

            <div class="license-legend mb-md">
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

            <div class="card">
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>License</th>
                                <th>SPDX ID</th>
                                <th>Category</th>
                                <th>Components</th>
                            </tr>
                        </thead>
                        <tbody>
                            <For each={sorted()}>
                                {(lic) => (
                                    <tr>
                                        <td>
                                            <A
                                                href={`/licenses/${lic.id}/components`}
                                            >
                                                {lic.name}
                                            </A>
                                        </td>
                                        <td>
                                            <Show
                                                when={lic.spdxId}
                                                fallback={
                                                    <span class="text-muted">
                                                        —
                                                    </span>
                                                }
                                            >
                                                <span class="badge badge-primary">
                                                    {lic.spdxId}
                                                </span>
                                            </Show>
                                        </td>
                                        <td>
                                            <span
                                                class={`badge ${CATEGORY_COLORS[lic.category]?.badge ?? ""}`}
                                            >
                                                {CATEGORY_COLORS[lic.category]
                                                    ?.label ?? lic.category}
                                            </span>
                                        </td>
                                        <td>{lic.componentCount}</td>
                                    </tr>
                                )}
                            </For>
                        </tbody>
                    </table>
                </div>
            </div>
        </>
    );
}
