import { For, createMemo } from "solid-js";
import { Card } from "~/components/ui";
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

    return (
        <Card style={{ "margin-bottom": "1rem", padding: "0.75rem 1rem" }}>
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
                                            style={{ cursor: "pointer", background: "none", border: "none", padding: 0, color: props.enricher === e ? "var(--color-secondary)" : "inherit", "font-weight": props.enricher === e ? "600" : "400" }}
                                            onClick={() => props.onEnricher(props.enricher === e ? "" : e)}
                                        >
                                            <code>{e}</code>
                                        </button>
                                    </td>
                                    <For each={ENRICH_STATES}>
                                        {(s) => (
                                            <td style={{ "text-align": "right" }}>
                                                <button
                                                    style={{ cursor: "pointer", background: "none", border: "none", padding: 0, color: matrix()[e][s] ? "inherit" : "var(--color-text-muted)" }}
                                                    onClick={() => props.onCell(e, s)}
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
        </Card>
    );
}
