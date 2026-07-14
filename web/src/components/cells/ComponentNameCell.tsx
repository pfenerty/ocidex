import { Show, For } from "solid-js";
import { A } from "@solidjs/router";

export function ComponentNameCell(props: {
    name: string;
    group?: string;
    purlTypes?: string[];
    href?: string;
}) {
    const inner = () => (
        <>
            <Show when={props.group !== undefined && props.group !== ""}>
                <span class="text-muted">{props.group}/</span>
            </Show>
            <strong>{props.name}</strong>
        </>
    );

    return (
        <>
            <Show when={props.href} fallback={inner()}>
                {(href) => <A href={href()}>{inner()}</A>}
            </Show>
            <For each={props.purlTypes}>
                {(pt) => (
                    <>
                        {" "}
                        <span class="badge-sm">{pt}</span>
                    </>
                )}
            </For>
        </>
    );
}
