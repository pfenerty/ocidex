import { Show, For } from "solid-js";
import type { JSX } from "solid-js";
import type { OCIMetadata } from "~/api/client";
import { formatDateTime } from "~/utils/format";
import {
    isGitHubUrl,
    gitHubCommitUrl,
    containerRegistryUrl,
    friendlyUrlDisplay,
} from "~/utils/oci";

// ---------------------------------------------------------------------------
// Inline SVG icons (stroke-based, matches existing sidebar/PurlLink style)
// ---------------------------------------------------------------------------

function OciIcon() {
    return (
        <svg
            width="16"
            height="16"
            viewBox="0 0 16 16"
            fill="none"
            stroke="currentColor"
            stroke-width="1.5"
            stroke-linecap="round"
            stroke-linejoin="round"
        >
            <rect x="1.5" y="4" width="13" height="9" rx="1.5" />
            <path d="M4.5 7v3M7.5 7v3M10.5 7v3" />
            <path d="M5 4V2.5h6V4" />
        </svg>
    );
}

function GitHubIcon() {
    return (
        <svg
            width="12"
            height="12"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
        >
            <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" />
        </svg>
    );
}

function ExternalLinkIcon() {
    return (
        <svg
            class="external-icon"
            width="12"
            height="12"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
        >
            <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
            <polyline points="15 3 21 3 21 9" />
            <line x1="10" y1="14" x2="21" y2="3" />
        </svg>
    );
}

function DocsIcon() {
    return (
        <svg
            width="12"
            height="12"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
        >
            <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" />
            <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z" />
        </svg>
    );
}

function ContainerIcon() {
    return (
        <svg
            width="12"
            height="12"
            viewBox="0 0 16 16"
            fill="none"
            stroke="currentColor"
            stroke-width="1.5"
            stroke-linecap="round"
            stroke-linejoin="round"
        >
            <rect x="1.5" y="4" width="13" height="9" rx="1.5" />
            <path d="M4.5 7v3M7.5 7v3M10.5 7v3" />
        </svg>
    );
}

// ---------------------------------------------------------------------------
// Helper components
// ---------------------------------------------------------------------------

/** A detail field whose value is a clickable link with an icon. */
function LinkedField(props: {
    label: string;
    url: string;
    icon?: () => JSX.Element;
    display?: string;
}) {
    return (
        <div class="detail-field">
            <span class="detail-label">{props.label}</span>
            <span class="detail-value">
                <a
                    href={props.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    class="purl-link"
                >
                    <Show when={props.icon}>{props.icon!()}</Show>
                    {props.display ?? friendlyUrlDisplay(props.url)}
                    <ExternalLinkIcon />
                </a>
            </span>
        </div>
    );
}

const OCI_SKIP_KEYS = new Set([
    "org.opencontainers.image.version",
    "org.opencontainers.image.source",
    "org.opencontainers.image.revision",
    "org.opencontainers.image.authors",
    "org.opencontainers.image.description",
    "org.opencontainers.image.base.name",
    "org.opencontainers.image.url",
    "org.opencontainers.image.documentation",
    "org.opencontainers.image.vendor",
    "org.opencontainers.image.licenses",
    "org.opencontainers.image.title",
    "org.opencontainers.image.base.digest",
    "org.opencontainers.image.created",
]);

/** Collapsible key/value annotations table, filtering out already-displayed keys. */
function AnnotationsSection(props: {
    title: string;
    annotations: Record<string, string>;
}) {
    const entries = () =>
        Object.entries(props.annotations).filter(
            ([k]) => !OCI_SKIP_KEYS.has(k),
        );

    return (
        <Show when={entries().length > 0}>
            <details class="mt-md">
                <summary
                    class="text-muted text-sm"
                    style={{ cursor: "pointer" }}
                >
                    {props.title} ({entries().length})
                </summary>
                <div class="table-wrapper mt-sm">
                    <table>
                        <thead>
                            <tr>
                                <th>Key</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            <For each={entries()}>
                                {([key, value]) => (
                                    <tr>
                                        <td class="mono text-sm">{key}</td>
                                        <td
                                            class="mono text-sm"
                                            style={{
                                                "word-break": "break-all",
                                            }}
                                        >
                                            {value}
                                        </td>
                                    </tr>
                                )}
                            </For>
                        </tbody>
                    </table>
                </div>
            </details>
        </Show>
    );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function ImageMetadataCard(props: {
    metadata: OCIMetadata;
    ingestedAt: string;
}) {
    const m = props.metadata;

    const buildTimeDisplay = () => {
        if (!m.created) return null;
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
        m.sourceUrl && isGitHubUrl(m.sourceUrl) ? GitHubIcon : undefined;
    const urlIcon = () =>
        m.url && isGitHubUrl(m.url) ? GitHubIcon : undefined;

    const revisionUrl = () => {
        if (!m.revision || !m.sourceUrl) return null;
        return gitHubCommitUrl(m.sourceUrl, m.revision);
    };

    const baseImageUrl = () =>
        m.baseName ? containerRegistryUrl(m.baseName) : null;

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
                <Show when={m.architecture || m.os}>
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
                    <LinkedField
                        label="Source"
                        url={m.sourceUrl!}
                        icon={sourceIcon()}
                    />
                </Show>

                {/* URL (new) */}
                <Show when={m.url && m.url !== m.sourceUrl}>
                    <LinkedField label="URL" url={m.url!} icon={urlIcon()} />
                </Show>

                {/* Documentation (new) */}
                <Show when={m.documentation}>
                    <LinkedField
                        label="Documentation"
                        url={m.documentation!}
                        icon={() => <DocsIcon />}
                    />
                </Show>

                {/* Revision */}
                <Show when={m.revision}>
                    <div class="detail-field">
                        <span class="detail-label">Revision</span>
                        <span class="detail-value mono text-sm">
                            <Show
                                when={revisionUrl()}
                                fallback={m.revision!.substring(0, 12)}
                            >
                                <a
                                    href={revisionUrl()!}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    class="purl-link"
                                >
                                    <GitHubIcon />
                                    {m.revision!.substring(0, 12)}
                                    <ExternalLinkIcon />
                                </a>
                            </Show>
                        </span>
                    </div>
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
                    <div class="detail-field">
                        <span class="detail-label">Base Image</span>
                        <span class="detail-value mono text-sm">
                            <Show when={baseImageUrl()} fallback={m.baseName}>
                                <a
                                    href={baseImageUrl()!}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    class="purl-link"
                                >
                                    <ContainerIcon />
                                    {m.baseName}
                                    <ExternalLinkIcon />
                                </a>
                            </Show>
                        </span>
                    </div>
                </Show>

                {/* Base Digest (new) */}
                <Show when={m.baseDigest}>
                    <div class="detail-field">
                        <span class="detail-label">Base Digest</span>
                        <span class="detail-value mono text-sm">
                            {m.baseDigest!.substring(0, 19)}
                        </span>
                    </div>
                </Show>
            </div>

            {/* Annotation sections */}
            <Show when={m.labels}>
                <AnnotationsSection
                    title="Config Labels"
                    annotations={m.labels!}
                />
            </Show>
            <Show when={m.manifestAnnotations}>
                <AnnotationsSection
                    title="Manifest Annotations"
                    annotations={m.manifestAnnotations!}
                />
            </Show>
            <Show when={m.indexAnnotations}>
                <AnnotationsSection
                    title="Index Annotations"
                    annotations={m.indexAnnotations!}
                />
            </Show>
        </div>
    );
}
