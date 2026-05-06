import { For, Show } from "solid-js";
import { Loading, ErrorBox } from "~/components/Feedback";
import { formatDateTime } from "~/utils/format";
import { useGetSystemStatus, useListRegistries } from "~/api/queries";

export function StatusTab() {
    const query = useGetSystemStatus();
    const registries = useListRegistries();
    const polledRegistries = () =>
        (registries.data?.data ?? []).filter(
            (r) => r.scan_mode === "poll" || r.scan_mode === "both"
        );

    return (
        <Show when={!query.isLoading} fallback={<Loading />}>
            <Show when={!query.isError} fallback={<ErrorBox error={query.error} />}>
                <div style={{ display: "flex", "flex-direction": "column", gap: "1.5rem" }}>

                    <div>
                        <div class="section-title" style={{ "margin-bottom": "0.75rem" }}>Services</div>
                        <div class="stats-grid">
                            <div class="stat-card">
                                <div class="stat-label">Enrichment</div>
                                <div class="stat-value" style={{ color: query.data?.enrichment.enabled === true ? "var(--color-success)" : "var(--color-text-muted)" }}>
                                    {query.data?.enrichment.enabled === true ? "Enabled" : "Disabled"}
                                </div>
                                <Show when={query.data?.enrichment.enabled === true}>
                                    <div style={{ "font-size": "0.8rem", "margin-top": "0.25rem", color: "var(--color-text-muted)" }}>
                                        {query.data?.enrichment.workers} workers · queue {query.data?.enrichment.queue_size}
                                    </div>
                                </Show>
                            </div>
                            <div class="stat-card">
                                <div class="stat-label">Scanner</div>
                                <div class="stat-value" style={{ color: query.data?.scanner.enabled === true ? "var(--color-success)" : "var(--color-text-muted)" }}>
                                    {query.data?.scanner.enabled === true ? "Enabled" : "Disabled"}
                                </div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-label">Poller</div>
                                <div class="stat-value" style={{ color: query.data?.scanner.poller_enabled === true ? "var(--color-success)" : "var(--color-text-muted)" }}>
                                    {query.data?.scanner.poller_enabled === true ? "Enabled" : "Disabled"}
                                </div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-label">NATS</div>
                                <div class="stat-value" style={{ color: query.data?.nats.enabled === true ? "var(--color-success)" : "var(--color-text-muted)" }}>
                                    {query.data?.nats.enabled === true ? "Enabled" : "Disabled"}
                                </div>
                                <Show when={query.data?.nats.enabled === true}>
                                    <div style={{ "font-size": "0.8rem", "margin-top": "0.25rem", color: "var(--color-text-muted)" }}>
                                        {query.data?.nats.url}
                                    </div>
                                </Show>
                            </div>
                        </div>
                    </div>

                    <div>
                        <div class="section-title" style={{ "margin-bottom": "0.75rem" }}>Scan Pipeline</div>
                        <div class="stats-grid">
                            <div class="stat-card">
                                <div class="stat-label">Queued</div>
                                <div class="stat-value" style={{ color: (query.data?.scan_jobs.queued ?? 0) > 0 ? "var(--color-warning)" : "inherit" }}>
                                    {query.data?.scan_jobs.queued ?? 0}
                                </div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-label">Running</div>
                                <div class="stat-value" style={{ color: (query.data?.scan_jobs.running ?? 0) > 0 ? "var(--color-success)" : "inherit" }}>
                                    {query.data?.scan_jobs.running ?? 0}
                                </div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-label">Succeeded (24 h)</div>
                                <div class="stat-value">{query.data?.scan_jobs.succeeded_24h ?? 0}</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-label">Failed (24 h)</div>
                                <div class="stat-value" style={{ color: (query.data?.scan_jobs.failed_24h ?? 0) > 0 ? "var(--color-error)" : "inherit" }}>
                                    {query.data?.scan_jobs.failed_24h ?? 0}
                                </div>
                            </div>
                        </div>
                    </div>

                    <div>
                        <div class="section-title" style={{ "margin-bottom": "0.75rem" }}>Infrastructure</div>
                        <div class="stats-grid">
                            <div class="stat-card">
                                <div class="stat-label">Database</div>
                                <div class="stat-value" style={{ color: query.data?.db.ok === true ? "var(--color-success)" : "var(--color-error)" }}>
                                    {query.data?.db.ok === true ? "OK" : "Error"}
                                </div>
                                <div style={{ "font-size": "0.8rem", "margin-top": "0.25rem", color: "var(--color-text-muted)" }}>
                                    {query.data?.db.latency_ms} ms
                                </div>
                            </div>
                        </div>
                    </div>

                    <Show when={polledRegistries().length > 0}>
                        <div>
                            <div class="section-title" style={{ "margin-bottom": "0.75rem" }}>Registry Polling</div>
                            <div class="card">
                                <div class="table-wrapper">
                                    <table>
                                        <thead>
                                            <tr>
                                                <th>Registry</th>
                                                <th>Scan Mode</th>
                                                <th>Last Polled</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <For each={polledRegistries()}>
                                                {(reg) => (
                                                    <tr>
                                                        <td>{reg.name}</td>
                                                        <td><span class="badge">{reg.scan_mode}</span></td>
                                                        <td style={{ color: reg.last_polled_at !== undefined ? "inherit" : "var(--color-text-muted)" }}>
                                                            {reg.last_polled_at !== undefined ? formatDateTime(reg.last_polled_at) : "Never"}
                                                        </td>
                                                    </tr>
                                                )}
                                            </For>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </Show>

                </div>
            </Show>
        </Show>
    );
}
