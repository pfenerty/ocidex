import { For, Show } from "solid-js";
import { A } from "@solidjs/router";
import { VisXYContainer, VisLine, VisGroupedBar, VisAxis } from "@unovis/solid";
import { Loading, ErrorBox } from "~/components/Feedback";
import type { CategoryCountEntry, DailyCountEntry } from "~/api/client";
import { CATEGORY_COLORS } from "~/utils/licenseUtils";
import { useDashboardStats } from "~/api/queries";

function GrowthChart(props: { data: DailyCountEntry[]; height?: number }) {
    const x = (_: DailyCountEntry, i: number) => i;
    const y = (d: DailyCountEntry) => d.count;
    const tickFormat = (tick: number | Date) => {
        const d = props.data[tick as number] as DailyCountEntry | undefined;
        return d?.day.slice(5) ?? "";
    };
    const numTicks = () => Math.min(props.data.length, 8);
    return (
        <VisXYContainer data={props.data} height={props.height ?? 180}>
            <VisLine x={x} y={y} />
            <VisAxis type="x" tickFormat={tickFormat} numTicks={numTicks()} />
            <VisAxis type="y" />
        </VisXYContainer>
    );
}

export function MetricsTab() {
    const query = useDashboardStats();

    const cats = () => query.data?.license_categories ?? [];
    const timeline = () => query.data?.ingestion_timeline ?? [];
    const pkgGrowth = () => query.data?.package_growth_timeline ?? [];
    const verGrowth = () => query.data?.version_growth_timeline ?? [];
    const topPkgs = () => query.data?.top_packages ?? [];

    const catX = (_: CategoryCountEntry, i: number) => i;
    const catY = (d: CategoryCountEntry) => d.component_count;
    const catColor = (d: CategoryCountEntry) =>
        CATEGORY_COLORS[d.category]?.bg ?? "var(--color-secondary)";
    const catTickFormat = (tick: number | Date) =>
        cats()[tick as number]?.category ?? "";

    const ingestX = (_: DailyCountEntry, i: number) => i;
    const ingestY = (d: DailyCountEntry) => d.count;
    const ingestTickFormat = (tick: number | Date) => {
        const d = timeline()[tick as number] as DailyCountEntry | undefined;
        return d?.day.slice(5) ?? "";
    };

    return (
        <Show when={!query.isLoading} fallback={<Loading />}>
            <Show when={!query.isError} fallback={<ErrorBox error={query.error} />}>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-label">Artifacts</div>
                        <div class="stat-value">
                            <A href="/artifacts">{query.data?.artifact_count ?? 0}</A>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">SBOMs</div>
                        <div class="stat-value">{query.data?.sbom_count ?? 0}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Packages</div>
                        <div class="stat-value">
                            <A href="/components">{query.data?.package_count ?? 0}</A>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Package Versions</div>
                        <div class="stat-value">{query.data?.version_count ?? 0}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Licenses</div>
                        <div class="stat-value">
                            <A href="/licenses">{query.data?.license_count ?? 0}</A>
                        </div>
                    </div>
                </div>

                <div style={{ display: "grid", "grid-template-columns": "1fr 1fr", gap: "1rem", "margin-bottom": "1.5rem" }}>
                    <div class="card">
                        <div class="card-header">
                            <h3>Unique Packages Over Time</h3>
                        </div>
                        <Show
                            when={pkgGrowth().length > 0}
                            fallback={<p class="text-muted text-sm">No data yet</p>}
                        >
                            <GrowthChart data={pkgGrowth()} />
                        </Show>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h3>Unique Package Versions Over Time</h3>
                        </div>
                        <Show
                            when={verGrowth().length > 0}
                            fallback={<p class="text-muted text-sm">No data yet</p>}
                        >
                            <GrowthChart data={verGrowth()} />
                        </Show>
                    </div>
                </div>

                <div style={{ display: "grid", "grid-template-columns": "1fr 1fr", gap: "1rem", "margin-bottom": "1.5rem" }}>
                    <div class="card">
                        <div class="card-header">
                            <h3>License Categories</h3>
                        </div>
                        <Show
                            when={cats().length > 0}
                            fallback={<p class="text-muted text-sm">No license data</p>}
                        >
                            <VisXYContainer data={cats()} height={160}>
                                <VisGroupedBar x={catX} y={[catY]} color={catColor} />
                                <VisAxis type="x" tickFormat={catTickFormat} numTicks={cats().length} />
                                <VisAxis type="y" />
                            </VisXYContainer>
                        </Show>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h3>30-Day Ingestion</h3>
                        </div>
                        <Show
                            when={timeline().length > 0}
                            fallback={<p class="text-muted text-sm">No ingestion data</p>}
                        >
                            <VisXYContainer data={timeline()} height={160}>
                                <VisLine x={ingestX} y={ingestY} />
                                <VisAxis type="x" tickFormat={ingestTickFormat} numTicks={Math.min(timeline().length, 10)} />
                                <VisAxis type="y" />
                            </VisXYContainer>
                        </Show>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <h3>Top Packages by Version Count</h3>
                    </div>
                    <Show
                        when={topPkgs().length > 0}
                        fallback={<p class="text-muted text-sm">No packages yet</p>}
                    >
                        <div class="table-wrapper">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Package</th>
                                        <th>Type</th>
                                        <th>Versions</th>
                                        <th>SBOMs</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <For each={topPkgs()}>
                                        {(pkg) => (
                                            <tr>
                                                <td>
                                                    <A href={`/components/overview?name=${encodeURIComponent(pkg.name)}${pkg.group !== undefined && pkg.group !== "" ? `&group=${encodeURIComponent(pkg.group)}` : ""}`}>
                                                        {pkg.group !== undefined && pkg.group !== "" ? `${pkg.group}/${pkg.name}` : pkg.name}
                                                    </A>
                                                </td>
                                                <td><span class="badge">{pkg.type}</span></td>
                                                <td>{pkg.version_count}</td>
                                                <td>{pkg.sbom_count}</td>
                                            </tr>
                                        )}
                                    </For>
                                </tbody>
                            </table>
                        </div>
                    </Show>
                </div>
            </Show>
        </Show>
    );
}
