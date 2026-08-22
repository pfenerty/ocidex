import type { JSX } from "solid-js";
import { For } from "solid-js";

export interface TabDef<T extends string> {
    id: T;
    label: JSX.Element;
    title?: string;
}

/**
 * TabBar renders the underlined tab strip. Every page that grew tabs
 * re-implemented the same `class={tab() === "x" ? "active" : ""}` ternary once
 * per tab, which is where a tab quietly stops highlighting: the ternary is
 * copy-pasted and one copy keeps the previous tab's id.
 */
export function TabBar<T extends string>(props: {
    tabs: readonly TabDef<T>[];
    active: T;
    onSelect: (id: T) => void;
    /** Appended to `.tab-bar`, for spacing utilities like `mb-4`. */
    class?: string;
    style?: JSX.CSSProperties;
}): JSX.Element {
    return (
        <div
            class={props.class !== undefined ? `tab-bar ${props.class}` : "tab-bar"}
            style={props.style}
        >
            <For each={props.tabs}>
                {(t) => (
                    <button
                        class={props.active === t.id ? "active" : ""}
                        title={t.title}
                        onClick={() => props.onSelect(t.id)}
                    >
                        {t.label}
                    </button>
                )}
            </For>
        </div>
    );
}
