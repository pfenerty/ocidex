import { Show } from "solid-js";
import type { OCIMetadata } from "~/api/client";
import { formatDateTime } from "~/utils/format";
import {
    isGitHubUrl,
    gitHubCommitUrl,
    containerRegistryUrl,
} from "~/utils/oci";
import {
    OciIcon,
    GitHubIcon,
    ExternalLinkIcon,
    DocsIcon,
    ContainerIcon,
} from "./metadata/OciIcons";
import { LinkedField } from "./metadata/LinkedField";
import { AnnotationsSection } from "./metadata/AnnotationsSection";

export default function ImageMetadataCard(props: {
    metadata: OCIMetadata;
    ingestedAt: string;
}) {
    // eslint-disable-next-line solid/reactivity
    const m = props.metadata;

    const buildTimeDisplay = () => {
        if (m.created === undefined) return null;
        const built = new Date(m.created);
        const ingested = new Date(props.ingestedAt);
        const diffMs = ingested.getTime() - built.getTime();
        const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
        let delta = "";
        if (diffDays > 0) {
            delta = ` (${diffDays}d before ingestion)`;
        }
        return formatDateTime(m.created) + delta;
    };

    const sourceIcon = () =>
        m.sourceUrl !== undefined && isGitHubUrl(m.sourceUrl) ? GitHubIcon : undefined;
    const urlIcon = () =>
        m.url !== undefined && isGitHubUrl(m.url) ? GitHubIcon : undefined;

    const revisionUrl = () => {
        if (m.revision === undefined || m.sourceUrl === undefined) return null;
        return gitHubCommitUrl(m.sourceUrl, m.revision);
    };

    const baseImageUrl = () =>
        m.baseName !== undefined ? containerRegistryUrl(m.baseName) : null;

    return (
        <div class="card mb-md">
            <div class="card-header">
                <h3
                    style={{
                        display: "flex",
                        "align-items": "center",
                        gap: "0.5rem",
                    }}
                >
                    <OciIcon />
                    <Show when={m.title} fallback="Image Metadata">
                        {m.title}
                    </Show>
                </h3>
                <span class="text-muted text-sm">
                    <Show when={m.title} fallback="from OCI registry">
                        Image Metadata
                    </Show>
                </span>
            </div>

            <div class="detail-grid">
                {/* Platform */}
                <Show when={Boolean(m.architecture) || Boolean(m.os)}>
                    <div class="detail-field">
                        <span class="detail-label">Platform</span>
                        <span class="detail-value">
                            {[m.os, m.architecture].filter(Boolean).join("/")}
                        </span>
                    </div>
                </Show>

                {/* Build time */}
                <Show when={buildTimeDisplay()}>
                    <div class="detail-field">
                        <span class="detail-label">Built</span>
                        <span class="detail-value">{buildTimeDisplay()}</span>
                    </div>
                </Show>

                {/* Image version */}
                <Show when={m.imageVersion}>
                    <div class="detail-field">
                        <span class="detail-label">Image Version</span>
                        <span class="detail-value">{m.imageVersion}</span>
                    </div>
                </Show>

                {/* Source URL */}
                <Show when={m.sourceUrl}>
                    {(src) => (
                        <LinkedField
                            label="Source"
                            url={src()}
                            icon={sourceIcon()}
                        />
                    )}
                </Show>

                {/* URL (new) */}
                <Show when={m.url !== undefined && m.url !== m.sourceUrl ? m.url : undefined}>
                    {(url) => <LinkedField label="URL" url={url()} icon={urlIcon()} />}
                </Show>

                {/* Documentation (new) */}
                <Show when={m.documentation}>
                    {(doc) => (
                        <LinkedField
                            label="Documentation"
                            url={doc()}
                            icon={() => <DocsIcon />}
                        />
                    )}
                </Show>

                {/* Revision */}
                <Show when={m.revision}>
                    {(rev) => (
                        <div class="detail-field">
                            <span class="detail-label">Revision</span>
                            <span class="detail-value mono text-sm">
                                <Show
                                    when={revisionUrl()}
                                    fallback={rev().substring(0, 12)}
                                >
                                    {(rUrl) => (
                                        <a
                                            href={rUrl()}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            class="purl-link"
                                        >
                                            <GitHubIcon />
                                            {rev().substring(0, 12)}
                                            <ExternalLinkIcon />
                                        </a>
                                    )}
                                </Show>
                            </span>
                        </div>
                    )}
                </Show>

                {/* Authors */}
                <Show when={m.authors}>
                    <div class="detail-field">
                        <span class="detail-label">Authors</span>
                        <span class="detail-value">{m.authors}</span>
                    </div>
                </Show>

                {/* Description */}
                <Show when={m.description}>
                    <div class="detail-field">
                        <span class="detail-label">Description</span>
                        <span class="detail-value">{m.description}</span>
                    </div>
                </Show>

                {/* Vendor (new) */}
                <Show when={m.vendor}>
                    <div class="detail-field">
                        <span class="detail-label">Vendor</span>
                        <span class="detail-value">{m.vendor}</span>
                    </div>
                </Show>

                {/* Licenses (new) */}
                <Show when={m.licenses}>
                    <div class="detail-field">
                        <span class="detail-label">Licenses</span>
                        <span class="detail-value">{m.licenses}</span>
                    </div>
                </Show>

                {/* Base Image */}
                <Show when={m.baseName}>
                    {(baseName) => (
                        <div class="detail-field">
                            <span class="detail-label">Base Image</span>
                            <span class="detail-value mono text-sm">
                                <Show when={baseImageUrl()} fallback={baseName()}>
                                    {(bUrl) => (
                                        <a
                                            href={bUrl()}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            class="purl-link"
                                        >
                                            <ContainerIcon />
                                            {baseName()}
                                            <ExternalLinkIcon />
                                        </a>
                                    )}
                                </Show>
                            </span>
                        </div>
                    )}
                </Show>

                {/* Base Digest (new) */}
                <Show when={m.baseDigest}>
                    {(digest) => (
                        <div class="detail-field">
                            <span class="detail-label">Base Digest</span>
                            <span class="detail-value mono text-sm">
                                {digest().substring(0, 19)}
                            </span>
                        </div>
                    )}
                </Show>
            </div>

            {/* Annotation sections */}
            <Show when={m.labels}>
                {(labels) => (
                    <AnnotationsSection
                        title="Config Labels"
                        annotations={labels()}
                    />
                )}
            </Show>
            <Show when={m.manifestAnnotations}>
                {(anns) => (
                    <AnnotationsSection
                        title="Manifest Annotations"
                        annotations={anns()}
                    />
                )}
            </Show>
            <Show when={m.indexAnnotations}>
                {(anns) => (
                    <AnnotationsSection
                        title="Index Annotations"
                        annotations={anns()}
                    />
                )}
            </Show>
        </div>
    );
}
