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
    /**
     * Extra content in the left column, below the subtitle — SBOMDetail's
     * copyable digest, VulnerabilityDetail's alias line.
     *
     * It exists because `subtitle` is wrapped in a `<p>`, and `.page-header p`
     * is what carries the muted colour and the 0.25rem top margin. A block
     * element passed as `subtitle` would be auto-closed out of that paragraph
     * by the parser and lose both. A caller with block content puts it here and
     * leaves `subtitle` unset.
     */
    meta?: JSX.Element;
    /**
     * Full-width content below the row, still inside `.page-header` so it sits
     * above the header's bottom margin — ClusterDetail's `<DetailGrid>`.
     */
    footer?: JSX.Element;
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
                    {props.meta}
                </div>
                <Show when={props.actions !== undefined}>{props.actions}</Show>
            </div>
            {props.footer}
        </div>
    );
}
