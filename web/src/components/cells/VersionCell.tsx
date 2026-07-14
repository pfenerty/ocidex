import { Show } from "solid-js";

export function VersionCell(props: { version?: string }) {
    return (
        <Show
            when={props.version !== undefined && props.version !== ""}
            fallback={<span class="text-muted">—</span>}
        >
            <span class="font-mono text-sm">{props.version}</span>
        </Show>
    );
}
