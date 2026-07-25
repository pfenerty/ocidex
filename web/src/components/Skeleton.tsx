import "./Skeleton.css";
import { Index } from "solid-js";
import type { JSX } from "solid-js";

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
            class={
                "skeleton" +
                (props.circle ? " skeleton-circle" : "") +
                (props.class ? ` ${props.class}` : "")
            }
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
        <div class={"skeleton-text" + (props.class ? ` ${props.class}` : "")} aria-hidden="true">
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
 * ```
 */
export function SkeletonTable(props: {
    columns: number;
    rows?: number;
    class?: string;
}): JSX.Element {
    const rowCount = (): number => props.rows ?? 8;
    return (
        <div class={"card" + (props.class ? ` ${props.class}` : "")} aria-hidden="true">
            <div class="table-wrapper">
                <table>
                    <tbody>
                        <Index each={Array.from({ length: rowCount() })}>
                            {() => (
                                <tr>
                                    <Index each={Array.from({ length: props.columns })}>
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
        <div class={"card skeleton-card" + (props.class ? ` ${props.class}` : "")} aria-hidden="true">
            <Skeleton width="40%" height="1.2em" />
            <SkeletonText lines={props.lines ?? 3} />
        </div>
    );
}
