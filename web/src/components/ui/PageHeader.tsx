import type { JSX } from "solid-js";
import { Show } from "solid-js";

/**
 * PageHeader emits the `.page-header` / `.page-header-row` structure that 19
 * page files hand-repeat today. It adds no CSS: the markup is exactly what
 * `components/Layout.css` already styles.
 *
 * The nesting is load-bearing. `.page-header-row` is
 * `justify-content: space-between`, so the title and subtitle must be wrapped
 * together in one child — emitting `h2`, `p` and `actions` as three siblings
 * spreads them across the row instead of pinning actions to the right.
 *
 * The subtitle carries no class: `.page-header p` already resolves to
 * `--color-text-muted`, so the `text-muted` some call sites add is a no-op.
 */
export function PageHeader(props: {
    title: JSX.Element;
    subtitle?: JSX.Element;
    /** Right-hand slot. Usually a `.btn-group`. */
    actions?: JSX.Element;
    /**
     * Rendered above the title. Detail pages currently emit their own
     * `.breadcrumb` div just before the header; this is where that moves in the
     * Phase 4 breadcrumb story.
     */
    breadcrumb?: JSX.Element;
}): JSX.Element {
    return (
        <div class="page-header">
            <Show when={props.breadcrumb !== undefined}>
                <div class="breadcrumb">{props.breadcrumb}</div>
            </Show>
            <div class="page-header-row">
                <div>
                    <h2>{props.title}</h2>
                    <Show when={props.subtitle !== undefined}>
                        <p>{props.subtitle}</p>
                    </Show>
                </div>
                <Show when={props.actions !== undefined}>{props.actions}</Show>
            </div>
        </div>
    );
}
