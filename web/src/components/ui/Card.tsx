import type { JSX } from "solid-js";
import { Show, splitProps } from "solid-js";
import { Dynamic } from "solid-js/web";

/**
 * Card is the field-guide surface from ADR-023. It exists so the `card` class
 * name and the `card > card-header > h3` nesting are written once instead of in
 * every page that happens to remember the shape.
 */
export type CardProps = {
    /**
     * The element to render. Two call sites need something other than a div for
     * real reasons: HomeDiscovery's landing panels are `<section>`s, and
     * Lookup's candidates are `<li>`s inside a list. Neither should have to stay
     * hand-written just to keep its tag.
     */
    as?: "div" | "section" | "li";
    /**
     * A card that announces rather than contains — a one-time secret, a notice
     * that edits here will be overwritten. Emits `.card-success` /
     * `.card-warning`, which set only the border colour.
     */
    tone?: "success" | "warning";
    children: JSX.Element;
} & JSX.HTMLAttributes<HTMLElement>;

export function Card(props: CardProps): JSX.Element {
    const [own, rest] = splitProps(props, ["as", "tone", "class", "children"]);
    const cls = (): string =>
        ["card", own.tone !== undefined ? `card-${own.tone}` : "", own.class ?? ""]
            .filter((c) => c !== "")
            .join(" ");
    return (
        <Dynamic component={own.as ?? "div"} class={cls()} {...rest}>
            {own.children}
        </Dynamic>
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
