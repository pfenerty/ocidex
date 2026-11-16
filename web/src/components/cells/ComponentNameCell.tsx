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
            {/* A package name is machine-written, so mono, as on the SBOM
                packages table (ocidex-iz0r.10). Weight 500, not bold: mono
                bold set the name heavier than anything else in the row. */}
            <Show when={props.group !== undefined && props.group !== ""}>
                <span class="font-mono text-muted">{props.group}/</span>
            </Show>
            <span class="font-mono font-medium">{props.name}</span>
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
