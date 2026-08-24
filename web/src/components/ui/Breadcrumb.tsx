import type { JSX } from "solid-js";
import { For, Show } from "solid-js";
import { A } from "@solidjs/router";

/** One step in the trail. Omit `href` for the page you are already on. */
export interface Crumb {
    /**
     * Nothing to name — `undefined`, `null` or `""` — drops the crumb entirely,
     * separator included. That is the "not found" case: the header never renders,
     * so the leaf has no name, and a trail ending in `Artifacts /` followed by a
     * skeleton that never resolves is worse than a trail of one.
     */
    label: JSX.Element;
    href?: string;
    /** Digests, purls and versions read better in the mono face. */
    mono?: boolean;
}

/**
 * The trail above a detail page's title, passed to `PageHeader`'s `breadcrumb`
 * slot.
 *
 * Seven pages hand-rolled this as a sibling `<div class="breadcrumb">` placed
 * *before* `<PageHeader>` — outside the header it belongs to, and each with its
 * own copy of the `<span class="separator">/</span>` interleaving. The CSS in
 * `Layout.css` is unchanged; this only stops the markup being retyped.
 *
 * A crumb with no `href` renders as text, which is what the last one always is:
 * a link to the page you are on is a link that does nothing. Every crumb before
 * it must have one — that is the whole point of a trail, and
 * `breadcrumbContract.test.ts` checks the app keeps it that way.
 */
export function Breadcrumb(props: { items: Crumb[] }): JSX.Element {
    const shown = (): Crumb[] =>
        props.items.filter((c) => c.label !== undefined && c.label !== null && c.label !== "");

    return (
        <For each={shown()}>
            {(item, i) => (
                <>
                    <Show when={i() > 0}>
                        <span class="separator">/</span>
                    </Show>
                    <Show
                        when={item.href !== undefined}
                        fallback={<span class={item.mono === true ? "font-mono" : undefined}>{item.label}</span>}
                    >
                        <A href={item.href ?? ""} class={item.mono === true ? "font-mono" : undefined}>
                            {item.label}
                        </A>
                    </Show>
                </>
            )}
        </For>
    );
}
