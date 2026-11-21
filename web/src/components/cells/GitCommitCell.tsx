import { Show } from "solid-js";
import { GitHubIcon, ExternalLinkIcon } from "~/components/metadata/OciIcons";
import { ExternalAnchor } from "~/components/ui/ExternalAnchor";

export function GitCommitCell(props: { sha: string; url?: string; subject?: string }) {
    const short = () => props.sha.substring(0, 12);

    return (
        <span class="font-mono text-sm" title={props.subject}>
            <Show when={props.url} fallback={short()}>
                {(url) => (
                    <ExternalAnchor url={url()} class="purl-link">
                        <GitHubIcon />
                        {short()}
                        <ExternalLinkIcon />
                    </ExternalAnchor>
                )}
            </Show>
        </span>
    );
}
