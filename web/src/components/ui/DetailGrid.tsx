import type { JSX } from "solid-js";
import { Show } from "solid-js";

/** DetailGrid is the auto-fit label/value grid used by every detail page. */
export function DetailGrid(props: { children: JSX.Element }): JSX.Element {
    return <div class="detail-grid">{props.children}</div>;
}

/**
 * DetailField is one label/value pair. `when` folds in the near-universal
 * "render this field only if the value is present" guard — passing it is
 * equivalent to wrapping the field in `<Show>`, but keeps the call site flat.
 */
export function DetailField(props: {
    label: JSX.Element;
    /** Extra classes on the value span, e.g. "font-mono text-sm". */
    valueClass?: string;
    /** When supplied and falsy, the whole field is omitted. */
    when?: unknown;
    children: JSX.Element;
}): JSX.Element {
    // `"when" in props` rather than a `undefined` check: an explicitly passed
    // `when={maybeUndefined}` must hide the field, which is exactly the case a
    // value-presence guard is used for.
    const visible = () => !("when" in props) || Boolean(props.when);
    return (
        <Show when={visible()}>
            <div class="detail-field">
                <span class="detail-label">{props.label}</span>
                <span class={props.valueClass !== undefined ? `detail-value ${props.valueClass}` : "detail-value"}>
                    {props.children}
                </span>
            </div>
        </Show>
    );
}
