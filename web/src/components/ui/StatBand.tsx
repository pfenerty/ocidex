import "../TileBand.css";
import type { JSX } from "solid-js";
import { For, Show } from "solid-js";
import { Dynamic } from "solid-js/web";

/**
 * One tile. How it behaves is derived from which navigation field is set —
 * there is no separate "interactive" flag to keep in sync:
 *
 *   `id`    → a button that reports to `onSelect`, and carries `.active` when it
 *             is the selected one. This is the SBOM band's shape.
 *   `href`  → a link. This is the cluster CoverageBand's shape.
 *   neither → a plain div. A tile that only reports a number must not look
 *             clickable. The SBOM vulnerability tile was one of these until
 *             ocidex-unn8.5 gave the page a tab to send the reader to; the
 *             artifact band's still is.
 */
export interface StatTile<T extends string = string> {
    id?: T;
    href?: string;
    /** Rendered before `head`, inside the same uppercase label row. */
    icon?: JSX.Element;
    head: JSX.Element;
    value: JSX.Element;
    sub?: JSX.Element;
    /**
     * Extra classes for the value span — in practice a badge class the caller
     * already computes (`trustBadgeClass`, a severity class). Deliberately
     * free-form rather than a fixed `tone` enum: the app's status vocabularies
     * live in `utils/trust.ts` and `VulnBadge.tsx`, and duplicating them here as
     * a third naming scheme is how they drift apart.
     */
    valueClass?: string;
}

/**
 * StatBand is the summary band from `pages/ClusterDetail`'s CoverageBand — the
 * strongest summary surface in the app — made generic and data-driven, so every
 * detail page can put the answer above the fold instead of inventing its own
 * top-of-page treatment (five different ones today).
 *
 * Styling is `components/TileBand.css`. The one change there is that the grid
 * fits as many tiles per row as will hold their content (`auto-fit`) instead of
 * a hardcoded four columns, which had been wrapping the SBOM band's fifth and
 * sixth tiles onto a row of their own. Tile count is therefore not a layout
 * input here — the band takes any number.
 */
export function StatBand<T extends string>(props: {
    tiles: readonly StatTile<T>[];
    active?: T;
    onSelect?: (id: T) => void;
    class?: string;
}): JSX.Element {
    return (
        <div class={props.class !== undefined ? `tile-band ${props.class}` : "tile-band"}>
            <For each={props.tiles}>
                {(t) => {
                    // Hoisted so the narrowing survives into the click handler.
                    const id = t.id;
                    return (
                    <Dynamic
                        component={id !== undefined ? "button" : t.href !== undefined ? "a" : "div"}
                        class={`tile ${id !== undefined && id === props.active ? "active" : ""}`}
                        href={t.href}
                        onClick={id !== undefined ? () => props.onSelect?.(id) : undefined}
                    >
                        <span class="tile-head">
                            {t.icon}
                            {t.head}
                        </span>
                        <span class={t.valueClass !== undefined ? `${t.valueClass} tile-value` : "tile-value"}>
                            {t.value}
                        </span>
                        <Show when={t.sub !== undefined}>
                            <span class="tile-sub">{t.sub}</span>
                        </Show>
                    </Dynamic>
                    );
                }}
            </For>
        </div>
    );
}
