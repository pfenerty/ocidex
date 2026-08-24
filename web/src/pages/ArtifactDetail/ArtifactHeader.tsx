import type { JSX } from "solid-js";
import { Show } from "solid-js";
import { A } from "@solidjs/router";
import type { ArtifactDetail } from "~/api/client";
import PurlLink from "~/components/PurlLink";
import CopyShareLink, { artifactLookupPath } from "~/components/CopyShareLink";
import WatchStar from "~/components/WatchStar";
import { Button, ButtonGroup, Card, DetailField, DetailGrid, PageHeader, TypeBadge } from "~/components/ui";
import { purlToRegistryUrl, purlTypeLabel } from "~/utils/purl";
import { artifactDisplayName, formatDateTime } from "~/utils/format";
import { containerRegistryUrl, detectRegistry } from "~/utils/oci";

/** ArtifactHeader is the title row: name (linked to its registry), counts, actions. */
export function ArtifactHeader(props: { artifact: ArtifactDetail; breadcrumb?: JSX.Element }) {
    const a = () => props.artifact;
    const registryPurl = () => {
        const purl = a().purl;
        return purl !== undefined && purlToRegistryUrl(purl) !== null ? purl : undefined;
    };

    return (
        <PageHeader
            breadcrumb={props.breadcrumb}
            title={
                <Show
                    when={a().type === "container" && detectRegistry(a().name) !== "redhat"}
                    fallback={artifactDisplayName(a())}
                >
                    <a href={containerRegistryUrl(a().name)} target="_blank" rel="noopener noreferrer">
                        {artifactDisplayName(a())}
                    </a>
                </Show>
            }
            /* Type only. The SBOM count and the first-tracked date are tiles in
               ArtifactBand now, and repeating them here was half of what made
               the old About card redundant. */
            subtitle={<TypeBadge type={a().type} />}
            actions={
                <ButtonGroup>
                    <WatchStar artifactId={a().id} watched={a().watched} />
                    <Show when={registryPurl()}>
                        {(purl) => (
                            <Button
                                as="a"
                                href={purlToRegistryUrl(purl()) ?? ""}
                                target="_blank"
                                rel="noopener noreferrer"
                                size="sm"
                                variant="primary"
                            >
                                View on {purlTypeLabel(purl()) ?? "Registry"}
                            </Button>
                        )}
                    </Show>
                    <Button as={A} href={`/diff`} size="sm">
                        Compare SBOMs
                    </Button>
                    <CopyShareLink path={artifactLookupPath(a())} />
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
