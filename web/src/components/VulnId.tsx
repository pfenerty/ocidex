import { Show } from "solid-js";
import { A } from "@solidjs/router";
import { aliasUrl } from "~/utils/vuln";

interface VulnIdProps {
    canonicalId: string;
    nativeId: string;
}

export function VulnId(props: VulnIdProps) {
    const canonical = () => props.canonicalId || props.nativeId;
    const showNative = () => canonical() !== props.nativeId;

    return (
        <span class="font-mono">
            <A href={`/vulnerabilities/${props.nativeId}`} class="text-sm">
                {canonical()}
            </A>
            <Show when={showNative()}>
                <br />
                <span class="text-muted text-xs">
                    {props.nativeId}
                </span>
            </Show>
        </span>
    );
}

export function VulnIdExternal(props: VulnIdProps) {
    const canonical = () => props.canonicalId || props.nativeId;
    const showNative = () => canonical() !== props.nativeId;

    return (
        <span class="font-mono">
            <a
                href={aliasUrl(canonical())}
                target="_blank"
                rel="noopener noreferrer"
                class="text-sm"
            >
                {canonical()}
            </a>
            <Show when={showNative()}>
                <br />
                <span class="text-muted text-xs">
                    {props.nativeId}
                </span>
            </Show>
        </span>
    );
}
