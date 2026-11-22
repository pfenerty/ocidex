import "./ArtifactGrid.css";
import { A } from "@solidjs/router";
import { For, Show, type JSX } from "solid-js";
import type { ArtifactSummary } from "~/api/client";
import type { SeenOnlyImage } from "~/api/queries";
import { Sprite } from "~/components/Sprite";
import { formatEntryNumber, artifactDisplayName } from "~/utils/format";

/**
 * The artifacts as numbered slots, in entry order: the entry number, the
 * artifact's sprite and its short name. A browsing view beside the table,
 * which stays the default for anything that needs sorting or counts.
 */
/** The repository's last path segment, without tag or digest. */
function repoName(ref: string): string {
    const noDigest = ref.split("@")[0];
    const last = noDigest.slice(noDigest.lastIndexOf("/") + 1);
    return last.split(":")[0];
}

export function ArtifactGrid(props: { artifacts: ArtifactSummary[]; seenOnly?: SeenOnlyImage[] }): JSX.Element {
    const ordered = () => props.artifacts.slice().sort((a, b) => a.entryNumber - b.entryNumber);
    const short = (a: ArtifactSummary) => {
        const name = artifactDisplayName(a);
        return name.slice(name.lastIndexOf("/") + 1);
    };
    return (
        <ul class="artifact-grid">
            <For each={ordered()}>
                {(a) => (
                    <li class="artifact-slot">
                        <A href={`/artifacts/${a.id}`} class="artifact-slot-link" title={artifactDisplayName(a)}>
                            <span class="artifact-slot-number">{formatEntryNumber(a.entryNumber)}</span>
                            <Sprite
                                class="artifact-slot-sprite"
                                size={40}
                                points={(a.criticalHistory ?? []).map((h) => ({ versionKey: h.versionKey, critical: h.critical }))}
                            />
                            <span class="artifact-slot-name">{short(a)}</span>
                        </A>
                    </li>
                )}
            </For>
            {/* Seen running on one of your clusters, not caught: no SBOM, so no
                entry number and no history. Each links to its cluster's gaps,
                where it can be ingested. */}
            <Show when={(props.seenOnly ?? []).length > 0}>
                <For each={props.seenOnly}>
                    {(img) => (
                        <li class="artifact-slot seen-only">
                            <a href={`/clusters/${img.clusterId}?tab=gaps`} class="artifact-slot-link" title={`${img.imageRef}: running with no SBOM`}>
                                <span class="artifact-slot-number">not caught</span>
                                <span class="artifact-slot-silhouette" aria-hidden="true">?</span>
                                <span class="artifact-slot-name">{repoName(img.imageRef)}</span>
                            </a>
                        </li>
                    )}
                </For>
            </Show>
        </ul>
    );
}
