import type { JSX } from "solid-js";
import { For } from "solid-js";

export interface SegmentedOption<T extends string> {
    id: T;
    label: JSX.Element;
    title?: string;
}

/**
 * Segmented switches how the content beside it is shown: Semver/All, Tree/List,
 * Scan/Enrichment jobs (ocidex-iz0r.5). One of three selection controls, each
 * with one job:
 *
 *   TabBar (nav)     switches what you are looking at
 *   Segmented        switches how it is shown
 *   TabBar (filter)  narrows the list (chips)
 *
 * Neutral, not blue: blue is navigation and filter state, and a view mode is
 * neither. Before this the same job was done by a solid-blue button pair, an
 * outlined-blue pair and a row of pills, sometimes three on one tab.
 */
export function Segmented<T extends string>(props: {
    options: readonly SegmentedOption<T>[];
    value: T;
    onChange: (id: T) => void;
    /** Names the choice for screen readers: "Version order", "Package view". */
    label: string;
    class?: string;
}): JSX.Element {
    return (
        <div
            class={props.class === undefined ? "segmented" : `segmented ${props.class}`}
            role="group"
            aria-label={props.label}
        >
            <For each={props.options}>
                {(o) => (
                    <button
                        type="button"
                        class={props.value === o.id ? "active" : ""}
                        aria-pressed={props.value === o.id}
                        title={o.title}
                        onClick={() => props.onChange(o.id)}
                    >
                        {o.label}
                    </button>
                )}
            </For>
        </div>
    );
}
