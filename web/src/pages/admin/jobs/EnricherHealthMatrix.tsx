import { createMemo } from "solid-js";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { useEnrichmentJobsSummary } from "~/api/queries";
import { JOB_STATE_COLORS } from "./jobCells";

export const ENRICHERS = ["user", "oci-metadata", "provenance"] as const;
export const ENRICH_STATES = ["queued", "running", "succeeded", "failed"] as const;

export type Enricher = (typeof ENRICHERS)[number];
export type EnrichState = (typeof ENRICH_STATES)[number];

/**
 * EnricherHealthMatrix is the enricher × state count grid. Every cell is a
 * filter shortcut into the table below it: clicking a count sets both filters,
 * clicking an enricher name toggles just that one.
 */
export function EnricherHealthMatrix(props: {
    enricher: Enricher | "";
    onEnricher: (e: Enricher | "") => void;
    onCell: (e: Enricher, s: EnrichState) => void;
}) {
    const summary = useEnrichmentJobsSummary();

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

    // Columns are built per render because each cell closes over the current
    // matrix and the caller's handlers. `header` takes JSX so the four state
    // columns keep the colours the badges use in the table below — a plain
    // string header could not, which is why this grid stayed hand-rolled.
    const columns = (): Column<Enricher>[] => [
        {
            header: "Enricher",
            render: (e) => (
                <button
                    class="cell-button"
                    classList={{ active: props.enricher === e }}
                    onClick={() => props.onEnricher(props.enricher === e ? "" : e)}
                >
                    <code>{e}</code>
                </button>
            ),
        },
        ...ENRICH_STATES.map((s) => ({
            header: <span style={{ color: JOB_STATE_COLORS[s] }}>{s}</span>,
            align: "right" as const,
            render: (e: Enricher) => (
                <button
                    class="cell-button"
                    classList={{ "text-muted": matrix()[e][s] === 0 }}
                    onClick={() => props.onCell(e, s)}
                >
                    {matrix()[e][s]}
                </button>
            ),
        })),
    ];

    return (
        <DataTable
            class="mb-4"
            // A state-by-enricher crosstab. One card per enricher listing
            // four counts is not the comparison this table exists to make.
            mobileLayout="scroll"
            caption={
                <p class="text-muted text-sm mb-2">
                    Per-enricher pipeline health — click a cell to filter
                </p>
            }
            columns={columns()}
            rows={[...ENRICHERS]}
            // The rows are the three enrichers, always present, so this never
            // shows a skeleton — it dims on refetch. What it does buy is the
            // error branch: a failed summary query used to render silently as
            // twelve zeros, which reads as a healthy pipeline.
            loading={summary.isFetching}
            isError={summary.isError}
            error={summary.error}
            emptyTitle="No enrichers configured"
        />
    );
}
