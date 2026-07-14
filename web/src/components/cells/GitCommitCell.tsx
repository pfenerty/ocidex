import { Show } from "solid-js";
import { GitHubIcon, ExternalLinkIcon } from "~/components/metadata/OciIcons";

export function GitCommitCell(props: { sha: string; url?: string; subject?: string }) {
    const short = () => props.sha.substring(0, 12);

    return (
        <span class="font-mono text-sm" title={props.subject}>
            <Show when={props.url} fallback={short()}>
                {(url) => (
                    <a href={url()} target="_blank" rel="noopener noreferrer" class="purl-link">
                        <GitHubIcon />
                        {short()}
                        <ExternalLinkIcon />
                    </a>
                )}
            </Show>
        </span>
    );
}
