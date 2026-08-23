import "./Admin.css";
import { Show } from "solid-js";
import { Loading } from "~/components/Feedback";
import { QueryBoundary } from "~/components/ui";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { TimestampCell } from "~/components/cells";
import { useGetSystemStatus, useListRegistries } from "~/api/queries";
import type { Registry } from "~/api/client";

/**
 * `sortValue` on every column, which the hand-rolled table had no way to offer.
 * "Never" sorts first ascending rather than last: a registry configured to poll
 * that has never been polled is the row this table exists to surface, and the
 * empty string puts it at the top.
 */
const pollColumns: Column<Registry>[] = [
    {
        header: "Registry",
        sortKey: "name",
        sortValue: (r) => r.name,
        render: (r) => r.name,
    },
    {
        header: "Scan Mode",
        sortKey: "scan_mode",
        sortValue: (r) => r.scan_mode,
        render: (r) => <span class="badge">{r.scan_mode}</span>,
    },
    {
        header: "Last Polled",
        sortKey: "last_polled_at",
        sortType: "numeric",
        sortValue: (r) => r.last_polled_at ?? "",
        render: (r) =>
            r.last_polled_at !== undefined ? (
                <TimestampCell iso={r.last_polled_at} />
            ) : (
                <span class="text-muted">Never</span>
            ),
    },
];

export function StatusTab() {
    const query = useGetSystemStatus();
    const registries = useListRegistries();
    const polledRegistries = () =>
        (registries.data?.data ?? []).filter(
            (r) => r.scan_mode === "poll" || r.scan_mode === "both"
        );

    return (
        <QueryBoundary query={query} loading={<Loading />}>
            {() => (
                <div style={{ display: "flex", "flex-direction": "column", gap: "1.5rem" }}>

                    <div>
                        <div class="section-title mb-3">Services</div>
                        <div class="stats-grid">
                            <div class="stat-card">
                                <div class="stat-label">Enrichment</div>
                                <div class="stat-value" style={{ color: query.data?.enrichment.enabled === true ? "var(--color-success)" : "var(--color-text-muted)" }}>
                                    {query.data?.enrichment.enabled === true ? "Enabled" : "Disabled"}
                                </div>
                                <Show when={query.data?.enrichment.enabled === true}>
                                    <div class="text-muted text-sm mt-1">
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
                                    <div class="text-muted text-sm mt-1">
                                        {query.data?.nats.url}
                                    </div>
                                </Show>
                            </div>
                        </div>
                    </div>

                    <div>
                        <div class="section-title mb-3">Scan Pipeline</div>
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
                        <div class="section-title mb-3">Infrastructure</div>
                        <div class="stats-grid">
                            <div class="stat-card">
                                <div class="stat-label">Database</div>
                                <div class="stat-value" style={{ color: query.data?.db.ok === true ? "var(--color-success)" : "var(--color-error)" }}>
                                    {query.data?.db.ok === true ? "OK" : "Error"}
                                </div>
                                <div class="text-muted text-sm mt-1">
                                    {query.data?.db.latency_ms} ms
                                </div>
                            </div>
                        </div>
                    </div>

                    <Show when={polledRegistries().length > 0}>
                        <div>
                            <div class="section-title mb-3">Registry Polling</div>
                            <DataTable
                                columns={pollColumns}
                                rows={polledRegistries()}
                                loading={registries.isFetching}
                                isError={registries.isError}
                                error={registries.error}
                                emptyTitle="No polled registries"
                            />
                        </div>
                    </Show>

                </div>
            )}
        </QueryBoundary>
    );
}
