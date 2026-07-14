import { For, Show, createEffect, createSignal, createMemo } from "solid-js";
import { A } from "@solidjs/router";
import { Loading, ErrorBox } from "~/components/Feedback";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { TimestampCell } from "~/components/cells";
import type { ScanJob, EnrichmentJob } from "~/api/client";
import {
    useListRegistries,
    useListScanJobs,
    useRetryScanJob,
    useRetryAllFailedScanJobs,
    useListEnrichmentJobs,
    useEnrichmentJobsSummary,
    useRetryEnrichmentJob,
    useRetryAllFailedEnrichmentJobs,
} from "~/api/queries";

const JOB_STATE_COLORS: Record<string, string> = {
    queued: "var(--color-text-muted)",
    running: "var(--color-primary)",
    succeeded: "var(--color-success)",
    failed: "var(--color-error, #e53e3e)",
};

const PAGE_SIZE = 20;
const ENRICHERS = ["user", "oci-metadata", "provenance"] as const;
const ENRICH_STATES = ["queued", "running", "succeeded", "failed"] as const;

type StateFilter = "active" | "running" | "queued" | "succeeded" | "failed" | "";
type Pipeline = "scan" | "enrichment";

export function JobsTab() {
    const [pipeline, setPipeline] = createSignal<Pipeline>("scan");
    return (
        <div>
            <div style={{ display: "flex", gap: "0.25rem", "margin-bottom": "1rem" }}>
                <button
                    class="btn"
                    aria-pressed={pipeline() === "scan"}
                    onClick={() => setPipeline("scan")}
                    style={pipeline() === "scan" ? { "border-color": "var(--color-primary)", color: "var(--color-primary)" } : {}}
                >
                    Scan jobs
                </button>
                <button
                    class="btn"
                    aria-pressed={pipeline() === "enrichment"}
                    onClick={() => setPipeline("enrichment")}
                    style={pipeline() === "enrichment" ? { "border-color": "var(--color-primary)", color: "var(--color-primary)" } : {}}
                >
                    Enrichment jobs
                </button>
            </div>
            <Show when={pipeline() === "scan"} fallback={<EnrichmentJobsView />}>
                <ScanJobsView />
            </Show>
        </div>
    );
}

function ScanJobsView() {
    const [offset, setOffset] = createSignal(0);
    const [expandedErrors, setExpandedErrors] = createSignal(new Set<string>());
    const [stateFilter, setStateFilter] = createSignal<StateFilter>("active");
    const [repoFilter, setRepoFilter] = createSignal("");
    const [registryFilter, setRegistryFilter] = createSignal("");
    const retry = useRetryScanJob();
    const retryAll = useRetryAllFailedScanJobs();

    const retryAllFailed = async () => {
        if (!confirm("Reset every 'failed' scan_jobs row back to 'queued'? This affects all failed rows, not just the visible page.")) {
            return;
        }
        try {
            const res = await retryAll.mutateAsync();
            alert(`Re-queued ${res.count} failed scan job${res.count === 1 ? "" : "s"}.`);
        } catch (err) {
            alert(`Retry all failed: ${err instanceof Error ? err.message : String(err)}`);
        }
    };

    const toggleError = (id: string) =>
        setExpandedErrors(prev => {
            const next = new Set(prev);
            if (next.has(id)) next.delete(id);
            else next.add(id);
            return next;
        });

    createEffect(() => { stateFilter(); repoFilter(); registryFilter(); setOffset(0); });

    const isActive = () => stateFilter() === "active";

    const qMain = useListScanJobs(() => {
        const f = stateFilter();
        return {
            state: f === "active" ? "running" : (f || undefined),
            limit: isActive() ? 50 : PAGE_SIZE,
            offset: isActive() ? 0 : offset(),
        };
    });
    const qQueued = useListScanJobs(() => ({ state: "queued" as const, limit: 50, offset: 0 }));
    const registries = useListRegistries();

    const isLoading = () => qMain.isLoading || (isActive() && qQueued.isLoading);
    const isError = () => qMain.isError || (isActive() && qQueued.isError);

    const displayJobs = () => {
        let jobs;
        if (isActive()) {
            const running = [...(qMain.data?.data ?? [])].sort(
                (a, b) => new Date(a.started_at ?? a.created_at).getTime() - new Date(b.started_at ?? b.created_at).getTime()
            );
            const queued = [...(qQueued.data?.data ?? [])].sort(
                (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
            );
            jobs = [...running, ...queued];
        } else {
            jobs = qMain.data?.data ?? [];
        }
        const repo = repoFilter().toLowerCase();
        const reg = registryFilter();
        return jobs.filter(job =>
            (!repo || job.repository.toLowerCase().includes(repo) || (job.tag ?? "").toLowerCase().includes(repo)) &&
            (!reg || job.registry_id === reg)
        );
    };

    const columns: Column<ScanJob>[] = [
        {
            header: "State",
            render: (job) => (
                <span class="badge" style={{ color: JOB_STATE_COLORS[job.state] ?? "inherit" }}>
                    {job.state}
                </span>
            ),
        },
        {
            header: "Image",
            render: (job) => (
                <>
                    <code>{job.tag !== undefined ? `${job.repository}:${job.tag}` : job.repository}</code>
                    <code style={{ display: "block", "font-size": "0.75rem", color: "var(--color-text-muted)", "margin-top": "0.15rem" }}>
                        {job.digest.replace(/^sha256:/, "").slice(0, 12)}
                    </code>
                </>
            ),
        },
        {
            header: "Worker",
            render: (job) => (
                <span style={{ "font-size": "0.8rem", color: "var(--color-text-muted)", "white-space": "nowrap" }}>
                    {job.worker_id ?? "—"}
                </span>
            ),
        },
        {
            header: "Attempts",
            render: (job) => <>{job.attempts}</>,
        },
        {
            header: "Created",
            render: (job) => <TimestampCell iso={job.created_at} />,
        },
        {
            header: "Last Error",
            render: (job) => (
                <Show when={job.last_error}>
                    <button
                        style={{ cursor: "pointer", "font-size": "0.85rem", background: "none", border: "none", padding: 0, color: "var(--color-primary)" }}
                        onClick={() => toggleError(job.id)}
                    >
                        {expandedErrors().has(job.id) ? "Hide error" : "View error"}
                    </button>
                    <Show when={expandedErrors().has(job.id)}>
                        <code style={{ "font-size": "0.8rem", "word-break": "break-all", display: "block", "margin-top": "0.25rem" }}>
                            {job.last_error}
                        </code>
                    </Show>
                </Show>
            ),
        },
        {
            header: "SBOM",
            render: (job) => (
                <Show when={job.sbom_id}>
                    <A href={`/sboms/${job.sbom_id}`} style={{ "font-size": "0.85rem" }}>
                        View SBOM
                    </A>
                </Show>
            ),
        },
        {
            header: "Actions",
            render: (job) => (
                <Show when={job.state === "failed"}>
                    <button
                        class="btn"
                        style={{ "font-size": "0.8rem", padding: "0.25rem 0.5rem" }}
                        disabled={retry.isPending}
                        onClick={() => retry.mutate(job.id)}
                    >
                        Retry
                    </button>
                </Show>
            ),
        },
    ];

    return (
        <Show when={!isLoading()} fallback={<Loading />}>
            <Show when={!isError()} fallback={<ErrorBox error={qMain.error} />}>
                <div style={{ display: "flex", gap: "0.75rem", "align-items": "center", "margin-bottom": "1rem", "flex-wrap": "wrap" }}>
                    <select value={stateFilter()} onInput={e => setStateFilter(e.currentTarget.value as StateFilter)}>
                        <option value="active">Active (Running + Queued)</option>
                        <option value="running">Running</option>
                        <option value="queued">Queued</option>
                        <option value="succeeded">Succeeded</option>
                        <option value="failed">Failed</option>
                        <option value="">All</option>
                    </select>
                    <input
                        type="text"
                        placeholder="Filter by repository…"
                        value={repoFilter()}
                        onInput={e => setRepoFilter(e.currentTarget.value)}
                    />
                    <select value={registryFilter()} onInput={e => setRegistryFilter(e.currentTarget.value)}>
                        <option value="">All registries</option>
                        <For each={registries.data?.data ?? []}>
                            {(r) => <option value={r.id}>{r.name}</option>}
                        </For>
                    </select>
                    <Show when={stateFilter() === "failed"}>
                        <button
                            class="btn"
                            disabled={retryAll.isPending}
                            onClick={() => { void retryAllFailed(); }}
                            style={{ "margin-left": "auto" }}
                        >
                            {retryAll.isPending ? "Re-queuing…" : "Retry all failed"}
                        </button>
                    </Show>
                </div>
                <DataTable
                    columns={columns}
                    rows={displayJobs()}
                    loading={false}
                    isError={false}
                    emptyTitle="No scan jobs found"
                    pagination={
                        !isActive() && qMain.data?.pagination
                            ? { pagination: qMain.data.pagination, onPageChange: setOffset }
                            : undefined
                    }
                />
            </Show>
        </Show>
    );
}

type EnrichState = "queued" | "running" | "succeeded" | "failed";
type Enricher = (typeof ENRICHERS)[number];

function EnrichmentJobsView() {
    const [offset, setOffset] = createSignal(0);
    const [expandedErrors, setExpandedErrors] = createSignal(new Set<string>());
    const [stateFilter, setStateFilter] = createSignal<EnrichState | "">("");
    const [enricherFilter, setEnricherFilter] = createSignal<Enricher | "">("");
    const [textFilter, setTextFilter] = createSignal("");
    const retry = useRetryEnrichmentJob();
    const retryAll = useRetryAllFailedEnrichmentJobs();
    const summary = useEnrichmentJobsSummary();

    createEffect(() => { stateFilter(); enricherFilter(); textFilter(); setOffset(0); });

    const q = useListEnrichmentJobs(() => ({
        state: stateFilter() || undefined,
        enricher_name: enricherFilter() || undefined,
        limit: PAGE_SIZE,
        offset: offset(),
    }));

    // matrix[enricher][state] = count
    const matrix = createMemo(() => {
        const m: Record<string, Record<string, number>> = {};
        for (const e of ENRICHERS) m[e] = { queued: 0, running: 0, succeeded: 0, failed: 0 };
        for (const row of summary.data?.data ?? []) {
            if ((ENRICHERS as readonly string[]).includes(row.enricher_name)) {
                m[row.enricher_name][row.state] = row.count;
            }
        }
        return m;
    });

    const toggleError = (id: string) =>
        setExpandedErrors(prev => {
            const next = new Set(prev);
            if (next.has(id)) next.delete(id);
            else next.add(id);
            return next;
        });

    const retryAllFailed = async () => {
        const scope = enricherFilter();
        const label = scope ? `'${scope}'` : "all enrichers";
        if (!confirm(`Reset every 'failed' enrichment_jobs row for ${label} back to 'queued'? This affects all failed rows, not just the visible page.`)) {
            return;
        }
        try {
            const res = await retryAll.mutateAsync(scope || undefined);
            alert(`Re-queued ${res.count} failed enrichment job${res.count === 1 ? "" : "s"}.`);
        } catch (err) {
            alert(`Retry all failed: ${err instanceof Error ? err.message : String(err)}`);
        }
    };

    const displayJobs = () => {
        const t = textFilter().toLowerCase();
        return (q.data?.data ?? []).filter(job =>
            !t ||
            (job.artifact_name ?? "").toLowerCase().includes(t) ||
            (job.sbom_digest ?? "").toLowerCase().includes(t)
        );
    };

    const columns: Column<EnrichmentJob>[] = [
        {
            header: "State",
            render: (job) => (
                <span class="badge" style={{ color: JOB_STATE_COLORS[job.state] ?? "inherit" }}>
                    {job.state}
                </span>
            ),
        },
        {
            header: "Enricher",
            render: (job) => <code>{job.enricher_name}</code>,
        },
        {
            header: "Image",
            render: (job) => (
                <>
                    <code>{job.artifact_name ?? "—"}</code>
                    <Show when={job.sbom_digest}>
                        <code style={{ display: "block", "font-size": "0.75rem", color: "var(--color-text-muted)", "margin-top": "0.15rem" }}>
                            {(job.sbom_digest ?? "").replace(/^sha256:/, "").slice(0, 12)}
                        </code>
                    </Show>
                </>
            ),
        },
        {
            header: "Worker",
            render: (job) => (
                <span style={{ "font-size": "0.8rem", color: "var(--color-text-muted)", "white-space": "nowrap" }}>
                    {job.worker_id ?? "—"}
                </span>
            ),
        },
        {
            header: "Attempts",
            render: (job) => <>{job.attempts}</>,
        },
        {
            header: "Created",
            render: (job) => <TimestampCell iso={job.created_at} />,
        },
        {
            header: "Last Error",
            render: (job) => (
                <Show when={job.last_error}>
                    <button
                        style={{ cursor: "pointer", "font-size": "0.85rem", background: "none", border: "none", padding: 0, color: "var(--color-primary)" }}
                        onClick={() => toggleError(job.id)}
                    >
                        {expandedErrors().has(job.id) ? "Hide error" : "View error"}
                    </button>
                    <Show when={expandedErrors().has(job.id)}>
                        <code style={{ "font-size": "0.8rem", "word-break": "break-all", display: "block", "margin-top": "0.25rem" }}>
                            {job.last_error}
                        </code>
                    </Show>
                </Show>
            ),
        },
        {
            header: "SBOM",
            render: (job) => (
                <Show when={job.sbom_id}>
                    <A href={`/sboms/${job.sbom_id}`} style={{ "font-size": "0.85rem" }}>
                        View SBOM
                    </A>
                </Show>
            ),
        },
        {
            header: "Actions",
            render: (job) => (
                <Show when={job.state === "failed"}>
                    <button
                        class="btn"
                        style={{ "font-size": "0.8rem", padding: "0.25rem 0.5rem" }}
                        disabled={retry.isPending}
                        onClick={() => retry.mutate(job.id)}
                    >
                        Retry
                    </button>
                </Show>
            ),
        },
    ];

    return (
        <div>
            <div class="card" style={{ "margin-bottom": "1rem", padding: "0.75rem 1rem" }}>
                <div style={{ "font-size": "0.85rem", color: "var(--color-text-muted)", "margin-bottom": "0.5rem" }}>
                    Per-enricher pipeline health — click a cell to filter
                </div>
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Enricher</th>
                                <For each={ENRICH_STATES}>
                                    {(s) => <th style={{ "text-align": "right", color: JOB_STATE_COLORS[s] }}>{s}</th>}
                                </For>
                            </tr>
                        </thead>
                        <tbody>
                            <For each={ENRICHERS}>
                                {(e) => (
                                    <tr>
                                        <td>
                                            <button
                                                style={{ cursor: "pointer", background: "none", border: "none", padding: 0, color: enricherFilter() === e ? "var(--color-primary)" : "inherit", "font-weight": enricherFilter() === e ? "600" : "400" }}
                                                onClick={() => setEnricherFilter(prev => prev === e ? "" : e)}
                                            >
                                                <code>{e}</code>
                                            </button>
                                        </td>
                                        <For each={ENRICH_STATES}>
                                            {(s) => (
                                                <td style={{ "text-align": "right" }}>
                                                    <button
                                                        style={{ cursor: "pointer", background: "none", border: "none", padding: 0, color: matrix()[e][s] ? "inherit" : "var(--color-text-muted)" }}
                                                        onClick={() => { setEnricherFilter(e); setStateFilter(s); }}
                                                    >
                                                        {matrix()[e][s]}
                                                    </button>
                                                </td>
                                            )}
                                        </For>
                                    </tr>
                                )}
                            </For>
                        </tbody>
                    </table>
                </div>
            </div>

            <div style={{ display: "flex", gap: "0.75rem", "align-items": "center", "margin-bottom": "1rem", "flex-wrap": "wrap" }}>
                <select value={stateFilter()} onInput={e => setStateFilter(e.currentTarget.value as EnrichState | "")}>
                    <option value="">All states</option>
                    <option value="running">Running</option>
                    <option value="queued">Queued</option>
                    <option value="succeeded">Succeeded</option>
                    <option value="failed">Failed</option>
                </select>
                <select value={enricherFilter()} onInput={e => setEnricherFilter(e.currentTarget.value as Enricher | "")}>
                    <option value="">All enrichers</option>
                    <For each={ENRICHERS}>
                        {(e) => <option value={e}>{e}</option>}
                    </For>
                </select>
                <input
                    type="text"
                    placeholder="Filter by artifact or digest…"
                    value={textFilter()}
                    onInput={e => setTextFilter(e.currentTarget.value)}
                />
                <Show when={stateFilter() === "failed"}>
                    <button
                        class="btn"
                        disabled={retryAll.isPending}
                        onClick={() => { void retryAllFailed(); }}
                        style={{ "margin-left": "auto" }}
                    >
                        {retryAll.isPending ? "Re-queuing…" : enricherFilter() ? `Retry all failed (${enricherFilter()})` : "Retry all failed"}
                    </button>
                </Show>
            </div>

            <Show when={!q.isLoading} fallback={<Loading />}>
                <Show when={!q.isError} fallback={<ErrorBox error={q.error} />}>
                    <DataTable
                        columns={columns}
                        rows={displayJobs()}
                        loading={false}
                        isError={false}
                        emptyTitle="No enrichment jobs found"
                        pagination={
                            q.data?.pagination
                                ? { pagination: q.data.pagination, onPageChange: setOffset }
                                : undefined
                        }
                    />
                </Show>
            </Show>
        </div>
    );
}
