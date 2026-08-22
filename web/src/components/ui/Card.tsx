import type { JSX } from "solid-js";
import { Show } from "solid-js";

/**
 * Card is the field-guide surface from ADR-023. It exists so the `card` class
 * name and the `card > card-header > h3` nesting are written once instead of in
 * every page that happens to remember the shape.
 */
export function Card(props: {
    class?: string;
    style?: JSX.CSSProperties;
    children: JSX.Element;
}): JSX.Element {
    return (
        <div class={props.class !== undefined ? `card ${props.class}` : "card"} style={props.style}>
            {props.children}
        </div>
    );
}

/**
 * CardHeader renders the title row. `count` is the muted badge convention used
 * for "how many rows are under this heading"; `actions` occupies the right-hand
 * slot the flexbox already reserves.
 *
 * The title and count are wrapped together rather than emitted as siblings of
 * `actions`. `.card-header` is `justify-content: space-between`, so three bare
 * children spread across the row and the badge ends up marooned in the middle,
 * reading as a stray number rather than as this heading's count.
 */
export function CardHeader(props: {
    title: JSX.Element;
    count?: number;
    actions?: JSX.Element;
}): JSX.Element {
    return (
        <div class="card-header">
            <div class="card-header-title">
                <h3>{props.title}</h3>
                <Show when={props.count !== undefined}>
                    <span class="badge">{props.count}</span>
                </Show>
            </div>
            <Show when={props.actions !== undefined}>{props.actions}</Show>
        </div>
    );
}
