import { For, Show, createEffect, createSignal } from "solid-js";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { Button, FilterBar, createExpandedSet } from "~/components/ui";
import { DEFAULT_PAGE_SIZE, type ScanJob } from "~/api/client";
import {
    useListRegistries,
    useListScanJobs,
    useRetryScanJob,
    useRetryAllFailedScanJobs,
} from "~/api/queries";
import {
    DigestLine,
    attemptsColumn,
    confirmRetryAll,
    createdColumn,
    lastErrorColumn,
    retryColumn,
    sbomColumn,
    stateColumn,
    workerColumn,
} from "./jobCells";

type StateFilter = "active" | "running" | "queued" | "succeeded" | "failed" | "";

export function ScanJobsView() {
    const [offset, setOffset] = createSignal(0);
    const expandedErrors = createExpandedSet();
    const [stateFilter, setStateFilter] = createSignal<StateFilter>("active");
    const [repoFilter, setRepoFilter] = createSignal("");
    const [registryFilter, setRegistryFilter] = createSignal("");
    const retry = useRetryScanJob();
    const retryAll = useRetryAllFailedScanJobs();

    createEffect(() => { stateFilter(); repoFilter(); registryFilter(); setOffset(0); });

    const isActive = () => stateFilter() === "active";

    const qMain = useListScanJobs(() => {
        const f = stateFilter();
        return {
            state: f === "active" ? "running" : (f || undefined),
            limit: isActive() ? 50 : DEFAULT_PAGE_SIZE,
            offset: isActive() ? 0 : offset(),
        };
    });
    const qQueued = useListScanJobs(() => ({ state: "queued" as const, limit: 50, offset: 0 }));
    const registries = useListRegistries();

    const isBusy = () => qMain.isFetching || (isActive() && qQueued.isFetching);
    const isError = () => qMain.isError || (isActive() && qQueued.isError);

    const displayJobs = () => {
        // First load (no data yet): return undefined so DataTable shows its
        // skeleton rather than the empty state.
        if (qMain.data === undefined) return undefined;
        let jobs;
        if (isActive()) {
            const running = [...(qMain.data.data ?? [])].sort(
                (a, b) => new Date(a.started_at ?? a.created_at).getTime() - new Date(b.started_at ?? b.created_at).getTime()
            );
            const queued = [...(qQueued.data?.data ?? [])].sort(
                (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
            );
            jobs = [...running, ...queued];
        } else {
            jobs = qMain.data.data ?? [];
        }
        const repo = repoFilter().toLowerCase();
        const reg = registryFilter();
        return jobs.filter(job =>
            (!repo || job.repository.toLowerCase().includes(repo) || (job.tag ?? "").toLowerCase().includes(repo)) &&
            (!reg || job.registry_id === reg)
        );
    };

    const columns: Column<ScanJob>[] = [
        stateColumn(),
        {
            header: "Image",
            render: (job) => (
                <>
                    <code>{job.tag !== undefined ? `${job.repository}:${job.tag}` : job.repository}</code>
                    <DigestLine digest={job.digest} />
                </>
            ),
        },
        workerColumn(),
        attemptsColumn(),
        createdColumn(),
        lastErrorColumn(expandedErrors),
        sbomColumn(),
        retryColumn(retry),
    ];

    return (
        <>
            <FilterBar>
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
                    <Button
                        class="ml-auto"
                        disabled={retryAll.isPending}
                        onClick={() => { void confirmRetryAll("", "scan", () => retryAll.mutateAsync()); }}
                    >
                        {retryAll.isPending ? "Re-queuing…" : "Retry all failed"}
                    </Button>
                </Show>
            </FilterBar>
            <DataTable
                columns={columns}
                rows={displayJobs()}
                loading={isBusy()}
                isError={isError()}
                error={qMain.error}
                emptyTitle="No scan jobs found"
                pagination={
                    !isActive() && qMain.data?.pagination
                        ? { pagination: qMain.data.pagination, onPageChange: setOffset }
                        : undefined
                }
            />
        </>
    );
}
