import type { JSX } from "solid-js";
import { Show } from "solid-js";

/**
 * FormField is a label above a control, with an optional muted (or emphasised)
 * hint after the label text. The registry dialog repeated this block fifteen
 * times with the same three inline style rules (now classes, since the CSP
 * forbids inline style attributes); the hint variant is what makes
 * a shared component worth having, since "(optional)" vs "(required for
 * ghcr.io)" differ only in tone.
 */
export function FormField(props: {
    label: JSX.Element;
    hint?: JSX.Element;
    /** Renders the hint in the error colour — for "required" qualifications. */
    hintEmphasis?: boolean;
    /** Spans the full width of a two-column grid. */
    fullWidth?: boolean;
    children: JSX.Element;
}): JSX.Element {
    return (
        <div classList={{ "col-span-full": props.fullWidth === true }}>
            <label class="mb-1 block text-[0.85rem]">
                {props.label}
                <Show when={props.hint !== undefined}>
                    {" "}
                    <span
                        class={
                            props.hintEmphasis === true
                                ? "font-bold text-[var(--color-danger)]"
                                : "text-[var(--color-text-muted)]"
                        }
                    >
                        {props.hint}
                    </span>
                </Show>
            </label>
            {props.children}
        </div>
    );
}

/** CheckboxField is a checkbox with its label on the same line. */
export function CheckboxField(props: {
    label: JSX.Element;
    checked: boolean;
    disabled?: boolean;
    onChange: (checked: boolean) => void;
}): JSX.Element {
    const enabled = () => props.disabled !== true;
    return (
        <label
            class="flex items-center gap-[0.4rem]"
            classList={{ "cursor-pointer": enabled(), "cursor-not-allowed opacity-40": !enabled() }}
        >
            <input
                type="checkbox"
                checked={props.checked}
                disabled={props.disabled}
                onChange={(e) => props.onChange(e.currentTarget.checked)}
            />
            {props.label}
        </label>
    );
}

/** FilterBar is the wrapping row of selects/inputs that sits above a table. */
export function FilterBar(props: { children: JSX.Element }): JSX.Element {
    return (
        <div class="mb-4 flex flex-wrap items-center gap-3">
            {props.children}
        </div>
    );
}
