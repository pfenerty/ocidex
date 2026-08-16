import { For, Show, createEffect, createSignal } from "solid-js";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { FilterBar, createExpandedSet } from "~/components/ui";
import { DEFAULT_PAGE_SIZE, type EnrichmentJob } from "~/api/client";
import {
    useListEnrichmentJobs,
    useRetryEnrichmentJob,
    useRetryAllFailedEnrichmentJobs,
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
import {
    ENRICHERS,
    EnricherHealthMatrix,
    type Enricher,
    type EnrichState,
} from "./EnricherHealthMatrix";

export function EnrichmentJobsView() {
    const [offset, setOffset] = createSignal(0);
    const expandedErrors = createExpandedSet();
    const [stateFilter, setStateFilter] = createSignal<EnrichState | "">("");
    const [enricherFilter, setEnricherFilter] = createSignal<Enricher | "">("");
    const [textFilter, setTextFilter] = createSignal("");
    const retry = useRetryEnrichmentJob();
    const retryAll = useRetryAllFailedEnrichmentJobs();

    createEffect(() => { stateFilter(); enricherFilter(); textFilter(); setOffset(0); });

    const q = useListEnrichmentJobs(() => ({
        state: stateFilter() || undefined,
        enricher_name: enricherFilter() || undefined,
        limit: DEFAULT_PAGE_SIZE,
        offset: offset(),
    }));

    const retryAllFailed = () => {
        const scope = enricherFilter();
        void confirmRetryAll(
            ` for ${scope ? `'${scope}'` : "all enrichers"}`,
            "enrichment",
            () => retryAll.mutateAsync(scope || undefined),
        );
    };

    const displayJobs = () => {
        // First load (no data yet): return undefined so DataTable shows its
        // skeleton rather than the empty state.
        if (q.data === undefined) return undefined;
        const t = textFilter().toLowerCase();
        return (q.data.data ?? []).filter(job =>
            !t ||
            (job.artifact_name ?? "").toLowerCase().includes(t) ||
            (job.sbom_digest ?? "").toLowerCase().includes(t)
        );
    };

    const columns: Column<EnrichmentJob>[] = [
        stateColumn(),
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
                        <DigestLine digest={job.sbom_digest ?? ""} />
                    </Show>
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
        <div>
            <EnricherHealthMatrix
                enricher={enricherFilter()}
                onEnricher={setEnricherFilter}
                onCell={(e, s) => { setEnricherFilter(e); setStateFilter(s); }}
            />

            <FilterBar>
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
                        onClick={retryAllFailed}
                        style={{ "margin-left": "auto" }}
                    >
                        {retryAll.isPending ? "Re-queuing…" : enricherFilter() ? `Retry all failed (${enricherFilter()})` : "Retry all failed"}
                    </button>
                </Show>
            </FilterBar>

            <DataTable
                columns={columns}
                rows={displayJobs()}
                loading={q.isLoading}
                isError={q.isError}
                error={q.error}
                emptyTitle="No enrichment jobs found"
                pagination={
                    q.data?.pagination
                        ? { pagination: q.data.pagination, onPageChange: setOffset }
                        : undefined
                }
            />
        </div>
    );
}
