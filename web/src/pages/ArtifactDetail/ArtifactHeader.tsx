import type { JSX } from "solid-js";
import { Show } from "solid-js";
import { A } from "@solidjs/router";
import type { ArtifactDetail } from "~/api/client";
import PurlLink from "~/components/PurlLink";
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
export function ArtifactHeader(props: { artifact: ArtifactDetail; breadcrumb?: JSX.Element }) {
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
                    <EntryLine kind="Artifact" id={a().id} />
                    <TypeBadge type={a().type} />
                </>
            }
            title={<TitleWithPrefix name={artifactDisplayName(a())} />}
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
                    <Button as={A} href={`/diff`} size="sm" variant="primary">
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
 */
export function ArtifactIdentity(props: { artifact: ArtifactDetail }) {
    const a = () => props.artifact;
    const hasIdentity = () =>
        (a().purl !== undefined && a().purl !== "") || (a().cpe !== undefined && a().cpe !== "");

    return (
        <details class="mb-4">
            <summary class="text-muted text-sm cursor-pointer">
                {hasIdentity() ? "Identity" : "Internal ID"}
            </summary>
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
