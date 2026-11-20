import "~/components/DetailSection.css";
import { Show } from "solid-js";
import type { JSX } from "solid-js";
import { ExternalLinkIcon } from "./OciIcons";
import { friendlyUrlDisplay } from "~/utils/oci";
import { ExternalAnchor } from "~/components/ui/ExternalAnchor";

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
                <ExternalAnchor url={props.url} class="purl-link">
                    <Show when={props.icon}>{(icon) => icon()()}</Show>
                    {props.display ?? friendlyUrlDisplay(props.url)}
                    <ExternalLinkIcon />
                </ExternalAnchor>
            </span>
        </div>
    );
}
