import { Show } from "solid-js";
import { A } from "@solidjs/router";
import type { ArtifactDetail } from "~/api/client";
import PurlLink from "~/components/PurlLink";
import CopyShareLink, { artifactLookupPath } from "~/components/CopyShareLink";
import { Card, CardHeader, DetailGrid, DetailField, TypeBadge, SigningBadge } from "~/components/ui";
import { purlToRegistryUrl, purlTypeLabel } from "~/utils/purl";
import { artifactDisplayName, formatDateTime, relativeDate, plural } from "~/utils/format";
import { containerRegistryUrl, detectRegistry } from "~/utils/oci";

/** ArtifactHeader is the title row: name (linked to its registry), counts, actions. */
export function ArtifactHeader(props: { artifact: ArtifactDetail }) {
    const a = () => props.artifact;
    const registryPurl = () => {
        const purl = a().purl;
        return purl !== undefined && purlToRegistryUrl(purl) !== null ? purl : undefined;
    };

    return (
        <div class="page-header">
            <div class="page-header-row">
                <div>
                    <h2>
                        <Show
                            when={a().type === "container" && detectRegistry(a().name) !== "redhat"}
                            fallback={artifactDisplayName(a())}
                        >
                            <a href={containerRegistryUrl(a().name)} target="_blank" rel="noopener noreferrer">
                                {artifactDisplayName(a())}
                            </a>
                        </Show>
                    </h2>
                    <p class="text-muted">
                        <TypeBadge type={a().type} /> {plural(a().sbomCount, "SBOM")}
                        {" · First tracked "}
                        {relativeDate(a().createdAt)}
                    </p>
                </div>
                <div class="btn-group">
                    <Show when={registryPurl()}>
                        {(purl) => (
                            <a
                                href={purlToRegistryUrl(purl()) ?? ""}
                                target="_blank"
                                rel="noopener noreferrer"
                                class="btn btn-sm btn-primary"
                            >
                                View on {purlTypeLabel(purl()) ?? "Registry"}
                            </a>
                        )}
                    </Show>
                    <A href={`/diff`} class="btn btn-sm">
                        Compare SBOMs
                    </A>
                    <CopyShareLink path={artifactLookupPath(a())} />
                </div>
            </div>
        </div>
    );
}

/**
 * ArtifactAboutCard is the identity summary. `isContainer` gates the image-only
 * rows: signing status on a library or binary would render as a permanent
 * "unsigned" that no amount of enrichment can change.
 */
export function ArtifactAboutCard(props: { artifact: ArtifactDetail; isContainer: boolean }) {
    const a = () => props.artifact;
    return (
        <Card class="mb-4">
            <CardHeader title="About this Artifact" />
            <DetailGrid>
                <DetailField label="Name">{a().name}</DetailField>
                <DetailField label="Type">
                    <TypeBadge type={a().type} />
                </DetailField>
                <DetailField label="Signing" when={props.isContainer}>
                    <SigningBadge status={a().signingStatus} />
                </DetailField>
                <DetailField label="Group" when={a().group}>
                    {a().group}
                </DetailField>
                <DetailField label="Package URL" when={a().purl}>
                    <PurlLink purl={a().purl ?? ""} showBadge />
                </DetailField>
                <DetailField label="CPE" when={a().cpe} valueClass="font-mono text-sm">
                    {a().cpe}
                </DetailField>
                <DetailField label="First Tracked">{formatDateTime(a().createdAt)}</DetailField>
            </DetailGrid>
            <details class="mt-4">
                <summary class="text-muted text-sm" style={{ cursor: "pointer" }}>
                    Internal ID
                </summary>
                <p class="font-mono text-sm mt-2" style={{ "word-break": "break-all" }}>
                    {a().id}
                </p>
            </details>
        </Card>
    );
}
