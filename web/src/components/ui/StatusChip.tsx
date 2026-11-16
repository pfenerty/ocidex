import type { JSX } from "solid-js";
import type { Status, Tone } from "~/utils/status";

/**
 * StatusChip renders one entry of a status map (~/utils/status): a dot and a
 * label, toned. The dot means the state reads without colour too; the unknown
 * tone is hatched and its dot hollow, so "never assessed" can't be mistaken for
 * a clean zero. `suffix` appends a detail such as " · 9m".
 */
export function StatusChip(props: { status: Status; suffix?: string; title?: string }): JSX.Element {
    return (
        <span class={`status-chip status-${props.status.tone}`} title={props.title ?? props.status.title}>
            {props.status.label}
            {props.suffix}
        </span>
    );
}

/** The fill class for a bar or legend swatch in a tone, matching StatusChip. */
export function toneFill(tone: Tone): string {
    return `tone-fill-${tone}`;
}
