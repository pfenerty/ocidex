import type { JSX } from "solid-js";
import { A } from "@solidjs/router";
import { Card, CardHeader, QueryBoundary } from "~/components/ui";
import { SkeletonText } from "~/components/Skeleton";

/**
 * Panel is the dashboard's section frame: a card, a heading, and a link to the
 * page that owns the data in full. The link is required rather than optional —
 * every panel here is a preview of something with a real page, and a preview
 * with no way through to the whole thing is a dead end.
 */
export function Panel(props: {
    title: string;
    icon?: JSX.Element;
    /** Where "see all" goes; also what the heading links to. */
    href: string;
    linkLabel?: string;
    count?: number;
    /**
     * Only alarm panels pass this, and they pass what their own query currently
     * says: "raised" when there is something wrong, "clear" when there is not,
     * "pending" while the query is still in flight.
     *
     * The dashboard used to give every panel identical weight, so a provenance
     * regression read exactly like a list of namespaces. This is what tells the
     * two apart — and "pending" is a distinct value rather than folded into
     * "clear" so a panel that is about to raise does not sink to the bottom of
     * the grid and jump back up a moment later (ocidex-ag4q.40).
     */
    alert?: "raised" | "clear" | "pending";
    children: JSX.Element;
}): JSX.Element {
    const alertClass = (): string | undefined => {
        switch (props.alert) {
            case "raised":
                return "dash-panel-alert";
            case "pending":
                return "dash-panel-pending";
            default:
                return undefined;
        }
    };

    return (
        <Card class={alertClass()}>
            <CardHeader
                title={
                    <>
                        {props.icon}
                        {props.title}
                    </>
                }
                count={props.count}
                actions={
                    <A href={props.href} class="dash-link">
                        {props.linkLabel ?? "See all"}
                    </A>
                }
            />
            {props.children}
        </Card>
    );
}

/**
 * PanelBody runs the loading / error / empty / rows ladder every panel shares.
 * It exists so the five panels differ only in the row they render — the shape
 * around them was identical five times over, and the empty case in particular
 * is easy to get wrong (an empty list is not an error, and must not render as
 * a permanent skeleton).
 */
export function PanelBody<T>(props: {
    query: {
        isLoading: boolean;
        isError: boolean;
        error: unknown;
        data: { data: T[] } | undefined;
    };
    /** Shown when the query succeeds with no rows. */
    empty: string;
    children: (rows: T[]) => JSX.Element;
}): JSX.Element {
    return (
        <QueryBoundary
            query={props.query}
            loading={<SkeletonText lines={3} />}
            empty={<p class="dash-empty">{props.empty}</p>}
            when={(d) => d.data.length > 0}
        >
            {(d) => <div class="dash-list">{props.children(d().data)}</div>}
        </QueryBoundary>
    );
}

/**
 * PanelRow is one line in a panel: a title, an optional subtitle, and a
 * right-aligned scrap of metadata (usually a timestamp or a count). Rendering
 * as an anchor keeps every row navigable, which is the acceptance criterion
 * "each linking to its detail view".
 */
export function PanelRow(props: {
    href: string;
    title: string;
    sub?: JSX.Element;
    meta?: JSX.Element;
}): JSX.Element {
    return (
        <A href={props.href} class="dash-row">
            <span class="dash-row-main">
                <span class="dash-row-title">{props.title}</span>
                {props.sub !== undefined && <span class="dash-row-sub">{props.sub}</span>}
            </span>
            {props.meta !== undefined && <span class="dash-row-meta">{props.meta}</span>}
        </A>
    );
}
