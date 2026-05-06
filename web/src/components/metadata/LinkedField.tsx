import { Show } from "solid-js";
import type { JSX } from "solid-js";
import { ExternalLinkIcon } from "./OciIcons";
import { friendlyUrlDisplay } from "~/utils/oci";

export function LinkedField(props: {
    label: string;
    url: string;
    icon?: () => JSX.Element;
    display?: string;
}) {
    return (
        <div class="detail-field">
            <span class="detail-label">{props.label}</span>
            <span class="detail-value">
                <a
                    href={props.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    class="purl-link"
                >
                    <Show when={props.icon}>{(icon) => icon()()}</Show>
                    {props.display ?? friendlyUrlDisplay(props.url)}
                    <ExternalLinkIcon />
                </a>
            </span>
        </div>
    );
}
