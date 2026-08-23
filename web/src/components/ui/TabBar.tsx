import type { JSX } from "solid-js";
import { For, Show } from "solid-js";
import { A } from "@solidjs/router";

export interface TabDef<T extends string> {
    id: T;
    label: JSX.Element;
    title?: string;
    /**
     * Render this tab as a link rather than a button.
     *
     * Admin's tabs are real routes, not local state — they have to stay
     * middle-clickable, copyable, and reachable by a bookmark. A tab strip that
     * is navigation and one that is a filter look the same today; ocidex-ag4q.44
     * separates those two meanings.
     */
    href?: string;
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
    /** Required for button tabs; link tabs navigate instead. */
    onSelect?: (id: T) => void;
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
                    <Show
                        when={t.href}
                        fallback={
                            <button
                                class={props.active === t.id ? "active" : ""}
                                title={t.title}
                                onClick={() => props.onSelect?.(t.id)}
                            >
                                {t.label}
                            </button>
                        }
                    >
                        {(href) => (
                            // The router's own active/inactive classes are
                            // renamed out of the way: its default match is a
                            // prefix one, so `/admin` would light up on
                            // `/admin/keys` too. `active` comes from the
                            // caller, which knows which tab it means.
                            <A
                                href={href()}
                                class={props.active === t.id ? "active" : ""}
                                activeClass="is-route-active"
                                inactiveClass="is-route-inactive"
                                title={t.title}
                            >
                                {t.label}
                            </A>
                        )}
                    </Show>
                )}
            </For>
        </div>
    );
}
