import "./StatBlock.css";
import { For, Show, type JSX } from "solid-js";

export interface StatRow {
    label: string;
    title: string;
    value: number | undefined;
    max: number;
    tone?: "critical" | "high";
}

/**
 * The artifact's figures as short labelled bars, each scaled against the
 * largest value of that figure in the catalog, so it reads at a glance whether
 * this artifact is big, long-lived or noisy compared with everything else
 * indexed. A row with no value (never scanned) is left out, not drawn as zero.
 */
export function StatBlock(props: { rows: StatRow[] }): JSX.Element {
    const shown = () => props.rows.filter((r) => r.value !== undefined && r.max > 0);
    return (
        <Show when={shown().length > 0}>
            <dl class="stat-block" aria-label="Compared with the largest in the catalog">
                <For each={shown()}>
                    {(r) => {
                        const pct = () => Math.min(100, ((r.value ?? 0) / r.max) * 100);
                        return (
                            <div class="stat-block-row" title={`${r.title}: ${(r.value ?? 0).toLocaleString()} of a catalog maximum of ${r.max.toLocaleString()}`}>
                                <dt>{r.label}</dt>
                                <dd class="stat-block-value">{(r.value ?? 0).toLocaleString()}</dd>
                                <dd class="stat-block-bar">
                                    <span
                                        class={r.tone === undefined ? "" : `stat-block-${r.tone}`}
                                        style={{ width: `${pct().toFixed(1)}%` }}
                                    />
                                </dd>
                            </div>
                        );
                    }}
                </For>
            </dl>
        </Show>
    );
}
