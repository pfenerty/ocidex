import { Show } from "solid-js";
import type { JSX } from "solid-js";
import { safeHref } from "~/utils/links";

/**
 * A link to an external URL that came from data: an SBOM, an image label, an
 * advisory. It opens in a new tab, and a URL safeHref refuses (javascript:,
 * data:, anything not http(s) or mailto) renders the same content as plain text
 * instead of a link.
 */
export function ExternalAnchor(props: {
    url: string | null | undefined;
    class?: string;
    title?: string;
    children: JSX.Element;
}) {
    return (
        <Show
            when={safeHref(props.url)}
            fallback={
                <span class={props.class} title={props.title}>
                    {props.children}
                </span>
            }
        >
            {(href) => (
                <a href={href()} target="_blank" rel="noopener noreferrer" class={props.class} title={props.title}>
                    {props.children}
                </a>
            )}
        </Show>
    );
}
