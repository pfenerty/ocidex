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
 * TabBar renders a strip of mutually exclusive choices. Every page that grew
 * tabs re-implemented the same `class={tab() === "x" ? "active" : ""}` ternary
 * once per tab, which is where a tab quietly stops highlighting: the ternary is
 * copy-pasted and one copy keeps the previous tab's id.
 *
 * `variant` picks which of the two jobs the strip is doing (ocidex-ag4q.44).
 * `nav` is the underlined strip: it changes *what you are looking at*, and some
 * of its tabs are real routes. `filter` is a row of pills: it narrows the list
 * already on screen. They rendered identically until now, so which one a strip
 * was could only be found out by clicking it. The behaviour is the same either
 * way — only the class the strip carries changes, and both stylesheets define
 * the same `button.active` contract.
 */
export function TabBar<T extends string>(props: {
    tabs: readonly TabDef<T>[];
    active: T;
    /** Required for button tabs; link tabs navigate instead. */
    onSelect?: (id: T) => void;
    /** Names the group for screen readers. Required for `filter` strips, whose
     *  pills ("All", "CRITICAL", …) do not say what they are filtering. */
    label?: string;
    /** "nav" changes what you are looking at; "filter" narrows it. */
    variant?: "nav" | "filter";
    /** Appended to the strip class, for spacing utilities like `mb-4`. */
    class?: string;
    style?: JSX.CSSProperties;
}): JSX.Element {
    const base = (): string => (props.variant === "filter" ? "filter-chips" : "tab-bar");

    return (
        <div
            class={props.class !== undefined ? `${base()} ${props.class}` : base()}
            style={props.style}
            role={props.variant === "filter" ? "group" : undefined}
            aria-label={props.variant === "filter" ? props.label : undefined}
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
