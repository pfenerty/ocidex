import type { JSX } from "solid-js";
import { Show } from "solid-js";
import { A } from "@solidjs/router";
import type { ArtifactDetail } from "~/api/client";
import PurlLink from "~/components/PurlLink";
import { Sprite } from "~/components/Sprite";
import { Shiny } from "~/components/Shiny";
import { entryText, type CriticalChange, type SeverityPoint } from "~/utils/versionDelta";
import CopyShareLink, { artifactLookupPath } from "~/components/CopyShareLink";
import WatchStar from "~/components/WatchStar";
import { Button, ButtonGroup, Card, DetailField, DetailGrid, EntryLine, PageHeader, TitleWithPrefix, TypeBadge } from "~/components/ui";
import { purlToRegistryUrl, purlTypeLabel } from "~/utils/purl";
import { artifactDisplayName, formatDateTime } from "~/utils/format";
import { containerRegistryUrl, detectRegistry } from "~/utils/oci";
import { safeHref } from "~/utils/links";

/**
 * ArtifactHeader is the title row: entry line, name, actions (ocidex-iz0r.6).
 *
 * The name used to *be* the registry link, which made the page title link-blue
 * and the one thing on the page that looked clickable for no visible reason.
 * The registry is an action now, beside Compare, which is the page's primary.
 */
/** The diff of the change the tile states, or an empty diff without one. */
export function compareHref(change: CriticalChange | undefined): string {
    if (change?.fromSbomId === undefined || change.toSbomId === undefined) return "/diff";
    return `/diff?from=${encodeURIComponent(change.fromSbomId)}&to=${encodeURIComponent(change.toSbomId)}`;
}

function compareTitle(change: CriticalChange | undefined): string | undefined {
    return change === undefined ? undefined : `Compare with ${change.previous}`;
}

export function ArtifactHeader(props: {
    artifact: ArtifactDetail;
    breadcrumb?: JSX.Element;
    points?: SeverityPoint[];
    shiny?: boolean;
    /** The change the vulnerabilities tile states; Compare opens it as a diff. */
    change?: CriticalChange;
}) {
    const a = () => props.artifact;
    const registryPurl = () => {
        const purl = a().purl;
        return purl !== undefined && purlToRegistryUrl(purl) !== null ? purl : undefined;
    };

    return (
        <PageHeader
            breadcrumb={props.breadcrumb}
            /* Type only beside the entry number. The SBOM count and the
               first-tracked date are tiles in ArtifactBand. */
            eyebrow={
                <>
                    <EntryLine kind="Artifact" id={a().id} number={a().entryNumber} />
                    <TypeBadge type={a().type} />
                    <Show when={props.shiny === true}>
                        <Shiny />
                    </Show>
                </>
            }
            title={
                <span class="with-sprite">
                    <Show when={props.points !== undefined && props.points.length > 0}>
                        <Sprite points={props.points ?? []} size={34} class="sprite-title" />
                    </Show>
                    <span>
                        <TitleWithPrefix name={artifactDisplayName(a())} />
                    </span>
                </span>
            }
            /* The entry: a two-line summary written from the version data. */
            subtitle={entryText(props.points ?? [], a().versionCount)}
            actions={
                <ButtonGroup>
                    <WatchStar artifactId={a().id} watched={a().watched} />
                    <Show
                        when={a().type === "container" && detectRegistry(a().name) !== "redhat"}
                        fallback={
                            <Show when={registryPurl()}>
                                {(purl) => (
                                    <Button
                                        as="a"
                                        href={safeHref(purlToRegistryUrl(purl()))}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        size="sm"
                                    >
                                        View on {purlTypeLabel(purl()) ?? "registry"}
                                    </Button>
                                )}
                            </Show>
                        }
                    >
                        <Button
                            as="a"
                            href={safeHref(containerRegistryUrl(a().name))}
                            target="_blank"
                            rel="noopener noreferrer"
                            size="sm"
                        >
                            View in registry
                        </Button>
                    </Show>
                    <CopyShareLink path={artifactLookupPath(a())} />
                    {/* Opens the change the tile states, both sides filled in; an
                        empty /diff made the reader find this artifact again.
                        Not the page's primary action: the answer is already on
                        the page, this is the detail behind it. */}
                    <Button as={A} href={compareHref(props.change)} size="sm" title={compareTitle(props.change)}>
                        Compare SBOMs
                    </Button>
                </ButtonGroup>
            }
        />
    );
}

/**
 * ArtifactIdentity is the machine-readable identity: package URL, CPE, and the
 * internal id. It replaces ArtifactAboutCard, which restated the header's name
 * and type in a full card above the fold and put signing status — the one fact
 * on it a reader actually needed — in the middle of a detail grid. Signing is a
 * band tile now; what is left is reference detail nobody reads on arrival, so it
 * starts collapsed.
 *
 * Group is not a row here: `artifactDisplayName` already prefixes it onto the
 * title, so a "Group" row was only ever a second rendering of the heading.
 *
 * The catalog comparison bars (`stats`) live here too. They restate the band's
 * figures against catalog maxima, which is reference detail rather than an
 * answer, so they do not earn a place above the tabs.
 */
export function ArtifactIdentity(props: { artifact: ArtifactDetail; stats?: JSX.Element }) {
    const a = () => props.artifact;
    return (
        <details class="mb-4">
            <summary class="text-muted text-sm cursor-pointer">Entry data</summary>
            {props.stats}
            <Card class="mt-2">
                <DetailGrid>
                    <DetailField label="Package URL" when={a().purl}>
                        <PurlLink purl={a().purl ?? ""} showBadge />
                    </DetailField>
                    <DetailField label="CPE" when={a().cpe} valueClass="font-mono text-sm">
                        {a().cpe}
                    </DetailField>
                    <DetailField label="First tracked">{formatDateTime(a().createdAt)}</DetailField>
                    <DetailField label="Internal ID" valueClass="font-mono text-sm break-all">
                        {a().id}
                    </DetailField>
                </DetailGrid>
            </Card>
        </details>
    );
}
