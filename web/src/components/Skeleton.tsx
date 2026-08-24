import "./Skeleton.css";
import { Index, Show } from "solid-js";
import type { JSX } from "solid-js";

/** Join class names, dropping falsy/undefined parts. */
const cx = (...parts: (string | false | undefined)[]): string => parts.filter(Boolean).join(" ");

/**
 * A single shimmer placeholder block. Decorative — hidden from assistive tech.
 *
 * @example
 * ```tsx
 * <Skeleton width="8rem" />                       // a title-width bar
 * <Skeleton circle width="2rem" height="2rem" />  // an avatar/badge
 * ```
 */
export function Skeleton(props: {
    width?: string;
    height?: string;
    radius?: string;
    circle?: boolean;
    /** Flow with surrounding text rather than breaking onto its own line. */
    inline?: boolean;
    class?: string;
    style?: JSX.CSSProperties;
}): JSX.Element {
    const style = (): JSX.CSSProperties => ({
        width: props.width ?? "100%",
        height: props.height ?? "1em",
        ...(props.radius !== undefined ? { "border-radius": props.radius } : {}),
        ...props.style,
    });
    return (
        <span
            class={cx("skeleton", props.circle === true && "skeleton-circle", props.inline === true && "skeleton-inline", props.class)}
            style={style()}
            aria-hidden="true"
        />
    );
}

/**
 * Stacked skeleton lines approximating a paragraph. The last line is rendered
 * narrower for a natural ragged edge.
 *
 * @example
 * ```tsx
 * <SkeletonText lines={3} />
 * ```
 */
export function SkeletonText(props: {
    lines?: number;
    width?: string;
    lastLineWidth?: string;
    class?: string;
}): JSX.Element {
    const count = (): number => props.lines ?? 3;
    return (
        <div class={cx("skeleton-text", props.class)} aria-hidden="true">
            <Index each={Array.from({ length: count() })}>
                {(_, i) => (
                    <Skeleton
                        width={
                            i === count() - 1 && count() > 1
                                ? (props.lastLineWidth ?? "60%")
                                : (props.width ?? "100%")
                        }
                    />
                )}
            </Index>
        </div>
    );
}

/**
 * A table-shaped placeholder for first-load list/table states. Markup mirrors
 * DataTable's `.card > .table-wrapper > table` so swapping between loading and
 * loaded states does not shift layout.
 *
 * @example
 * ```tsx
 * <SkeletonTable columns={4} rows={8} />
 * <SkeletonTable headers={["Name", "Type", "Version"]} />
 * ```
 */
export function SkeletonTable(props: {
    /** Column count. Optional when `headers` is given (defaults to headers.length). */
    columns?: number;
    /** When provided, renders a real <thead> with these labels. */
    headers?: string[];
    rows?: number;
    class?: string;
}): JSX.Element {
    const rowCount = (): number => props.rows ?? 8;
    const colCount = (): number => props.columns ?? props.headers?.length ?? 1;
    return (
        <div class={cx("card", props.class)} aria-hidden="true">
            <div class="table-wrapper">
                <table>
                    <Show when={props.headers}>
                        {(headers) => (
                            <thead>
                                <tr>
                                    <Index each={headers()}>
                                        {(header) => <th>{header()}</th>}
                                    </Index>
                                </tr>
                            </thead>
                        )}
                    </Show>
                    <tbody>
                        <Index each={Array.from({ length: rowCount() })}>
                            {() => (
                                <tr>
                                    <Index each={Array.from({ length: colCount() })}>
                                        {() => (
                                            <td>
                                                <Skeleton />
                                            </td>
                                        )}
                                    </Index>
                                </tr>
                            )}
                        </Index>
                    </tbody>
                </table>
            </div>
        </div>
    );
}

/**
 * A card-wrapped placeholder for metadata/detail sections: a short title bar
 * over a block of skeleton text.
 *
 * @example
 * ```tsx
 * <SkeletonCard lines={4} />
 * ```
 */
export function SkeletonCard(props: { lines?: number; class?: string }): JSX.Element {
    return (
        <div class={cx("card skeleton-card", props.class)} aria-hidden="true">
            <Skeleton width="40%" height="1.2em" />
            <SkeletonText lines={props.lines ?? 3} />
        </div>
    );
}

/**
 * A placeholder for a detail-page hero. Renders the real `.page-header` /
 * `.page-header-row` structure (see Layout.css) so there is no layout shift
 * when the loaded header replaces it.
 *
 * @example
 * ```tsx
 * <Show when={!query.isLoading} fallback={<SkeletonHeader />}>
 *     …the real page header…
 * </Show>
 * ```
 */
export function SkeletonHeader(props: { subtitleLines?: number; class?: string }): JSX.Element {
    return (
        <div class={cx("page-header", props.class)} aria-hidden="true">
            <div class="page-header-row">
                <div>
                    <Skeleton width="16rem" height="1.5rem" />
                    <div class="mt-2">
                        <SkeletonText
                            lines={props.subtitleLines ?? 1}
                            width="24rem"
                            lastLineWidth="18rem"
                        />
                    </div>
                </div>
            </div>
        </div>
    );
}
