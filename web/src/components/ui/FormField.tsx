import type { JSX } from "solid-js";
import { Show } from "solid-js";

const labelStyle: JSX.CSSProperties = {
    display: "block",
    "margin-bottom": "0.25rem",
    "font-size": "0.85rem",
};

/**
 * FormField is a label above a control, with an optional muted (or emphasised)
 * hint after the label text. The registry dialog repeated this block fifteen
 * times with the same three inline style rules; the hint variant is what makes
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
        <div style={props.fullWidth === true ? { "grid-column": "1 / -1" } : undefined}>
            <label style={labelStyle}>
                {props.label}
                <Show when={props.hint !== undefined}>
                    {" "}
                    <span
                        style={
                            props.hintEmphasis === true
                                ? { color: "var(--color-error, #e53e3e)", "font-weight": "bold" }
                                : { color: "var(--color-text-muted)" }
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
            style={{
                display: "flex",
                "align-items": "center",
                gap: "0.4rem",
                cursor: enabled() ? "pointer" : "not-allowed",
                opacity: enabled() ? 1 : 0.4,
            }}
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
        <div
            style={{
                display: "flex",
                gap: "0.75rem",
                "align-items": "center",
                "margin-bottom": "1rem",
                "flex-wrap": "wrap",
            }}
        >
            {props.children}
        </div>
    );
}
