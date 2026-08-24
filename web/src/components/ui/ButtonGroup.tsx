import type { JSX } from "solid-js";

/**
 * A row of related `<Button>`s that read as one control — the Tree/List toggle,
 * the artifact page's view switcher, the SBOM header's link cluster.
 *
 * This exists because `.btn-group` is a *container* class, not a button class,
 * and the two were indistinguishable while both were hand-written strings. The
 * distinction is load-bearing: `index.css` styles `.btn-group .btn.active` as a
 * pressed toggle, so a `.btn.active` outside a group is styled by nothing at
 * all. Giving the container its own primitive keeps that pairing in one place
 * and leaves `class="btn…"` with exactly one legitimate home per element kind.
 */
export function ButtonGroup(props: { class?: string; children?: JSX.Element }): JSX.Element {
    return (
        <div class={props.class === undefined ? "btn-group" : `btn-group ${props.class}`}>
            {props.children}
        </div>
    );
}
