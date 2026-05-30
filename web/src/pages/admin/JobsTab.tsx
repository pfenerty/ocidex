import { For, Show, createEffect, createSignal } from "solid-js";
import { A } from "@solidjs/router";
import { Loading, ErrorBox } from "~/components/Feedback";
import { formatDateTime } from "~/utils/format";
import { useListRegistries, useListScanJobs, useListScanJobFailures } from "~/api/queries";

const JOB_STATE_COLORS: Record<string, string> = {
    queued: "var(--color-text-muted)",
    running: "var(--color-primary)",
    succeeded: "var(--color-success)",
    failed: "var(--color-error, #e53e3e)",
};

const PAGE_SIZE = 20;

type StateFilter = "active" | "running" | "queued" | "succeeded" | "failed" | "";
type View = "jobs" | "dlq";

export function JobsTab() {
    const [view, setView] = createSignal<View>("jobs");
    const [page, setPage] = createSignal(0);
    const [expandedErrors, setExpandedErrors] = createSignal(new Set<string>());
    const [stateFilter, setStateFilter] = createSignal<StateFilter>("active");
    const [repoFilter, setRepoFilter] = createSignal("");
    const [registryFilter, setRegistryFilter] = createSignal("");

    const toggleError = (id: string) =>
        setExpandedErrors(prev => {
            const next = new Set(prev);
            if (next.has(id)) next.delete(id);
            else next.add(id);
            return next;
        });

    createEffect(() => { view(); stateFilter(); repoFilter(); registryFilter(); setPage(0); });

    const isActive = () => stateFilter() === "active";

    const qMain = useListScanJobs(() => {
        const f = stateFilter();
        return {
            state: f === "active" ? "running" : (f || undefined),
            limit: isActive() ? 50 : PAGE_SIZE,
            offset: isActive() ? 0 : page() * PAGE_SIZE,
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

    const total = () => qMain.data?.pagination.total ?? 0;
    const pageCount = () => Math.max(1, Math.ceil(total() / PAGE_SIZE));

    const qDLQ = useListScanJobFailures(() => ({
        limit: PAGE_SIZE,
        offset: view() === "dlq" ? page() * PAGE_SIZE : 0,
    }));
    const dlqTotal = () => qDLQ.data?.pagination.total ?? 0;
    const dlqPageCount = () => Math.max(1, Math.ceil(dlqTotal() / PAGE_SIZE));

    const viewTabStyle = (active: boolean) => ({
        cursor: "pointer",
        background: active ? "var(--color-primary)" : "transparent",
        color: active ? "var(--color-bg)" : "var(--color-text)",
        border: "1px solid var(--color-border)",
        padding: "0.35rem 0.75rem",
        "border-radius": "4px",
    });

    return (
        <Show when={view() === "jobs"} fallback={
            <Show when={!qDLQ.isLoading} fallback={<Loading />}>
                <Show when={!qDLQ.isError} fallback={<ErrorBox error={qDLQ.error} />}>
                    <div style={{ display: "flex", gap: "0.5rem", "margin-bottom": "1rem" }}>
                        <button style={viewTabStyle(false)} onClick={() => setView("jobs")}>Scan Jobs</button>
                        <button style={viewTabStyle(true)} onClick={() => setView("dlq")}>Dead Letter ({dlqTotal()})</button>
                    </div>
                    <div class="card">
                        <div class="table-wrapper">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Created</th>
                                        <th>NATS Msg ID</th>
                                        <th>Delivery Attempts</th>
                                        <th>Failure Reason</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <For each={qDLQ.data?.data ?? []}>
                                        {(row) => (
                                            <tr>
                                                <td style={{ "white-space": "nowrap" }}>{formatDateTime(row.created_at)}</td>
                                                <td><code style={{ "font-size": "0.8rem" }}>{row.nats_msg_id ?? "—"}</code></td>
                                                <td>{row.delivery_count}</td>
                                                <td><code style={{ "font-size": "0.8rem", "word-break": "break-all" }}>{row.failure_reason}</code></td>
                                            </tr>
                                        )}
                                    </For>
                                </tbody>
                            </table>
                        </div>
                        <Show when={dlqPageCount() > 1}>
                            <div style={{ display: "flex", gap: "0.5rem", "align-items": "center", "margin-top": "1rem", "justify-content": "flex-end" }}>
                                <button class="btn" disabled={page() === 0} onClick={() => setPage(p => p - 1)}>Prev</button>
                                <span style={{ "font-size": "0.85rem" }}>Page {page() + 1} of {dlqPageCount()}</span>
                                <button class="btn" disabled={page() + 1 >= dlqPageCount()} onClick={() => setPage(p => p + 1)}>Next</button>
                            </div>
                        </Show>
                    </div>
                </Show>
            </Show>
        }>
        <Show when={!isLoading()} fallback={<Loading />}>
            <Show when={!isError()} fallback={<ErrorBox error={qMain.error} />}>
                <div style={{ display: "flex", gap: "0.5rem", "margin-bottom": "1rem" }}>
                    <button style={viewTabStyle(true)} onClick={() => setView("jobs")}>Scan Jobs</button>
                    <button style={viewTabStyle(false)} onClick={() => setView("dlq")}>Dead Letter ({dlqTotal()})</button>
                </div>
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
                </div>
                <div class="card">
                    <div class="table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>State</th>
                                    <th>Image</th>
                                    <th>Worker</th>
                                    <th>Attempts</th>
                                    <th>Created</th>
                                    <th>Last Error</th>
                                    <th>SBOM</th>
                                </tr>
                            </thead>
                            <tbody>
                                <For each={displayJobs()}>
                                    {(job) => (
                                        <tr>
                                            <td>
                                                <span class="badge" style={{ color: JOB_STATE_COLORS[job.state] ?? "inherit" }}>
                                                    {job.state}
                                                </span>
                                            </td>
                                            <td>
                                                <code>{job.tag !== undefined ? `${job.repository}:${job.tag}` : job.repository}</code>
                                                <code style={{ display: "block", "font-size": "0.75rem", color: "var(--color-text-muted)", "margin-top": "0.15rem" }}>
                                                    {job.digest.replace(/^sha256:/, "").slice(0, 12)}
                                                </code>
                                            </td>
                                            <td style={{ "font-size": "0.8rem", color: "var(--color-text-muted)", "white-space": "nowrap" }}>
                                                {job.worker_id ?? "—"}
                                            </td>
                                            <td>{job.attempts}</td>
                                            <td style={{ "white-space": "nowrap" }}>{formatDateTime(job.created_at)}</td>
                                            <td>
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
                                            </td>
                                            <td>
                                                <Show when={job.sbom_id}>
                                                    <A href={`/sboms/${job.sbom_id}`} style={{ "font-size": "0.85rem" }}>
                                                        View SBOM
                                                    </A>
                                                </Show>
                                            </td>
                                        </tr>
                                    )}
                                </For>
                            </tbody>
                        </table>
                    </div>
                    <Show when={!isActive() && pageCount() > 1}>
                        <div style={{ display: "flex", gap: "0.5rem", "align-items": "center", "margin-top": "1rem", "justify-content": "flex-end" }}>
                            <button class="btn" disabled={page() === 0} onClick={() => setPage(p => p - 1)}>Prev</button>
                            <span style={{ "font-size": "0.85rem" }}>Page {page() + 1} of {pageCount()}</span>
                            <button class="btn" disabled={page() + 1 >= pageCount()} onClick={() => setPage(p => p + 1)}>Next</button>
                        </div>
                    </Show>
                </div>
            </Show>
        </Show>
        </Show>
    );
}
