import "~/components/DetailSection.css";
import { Show } from "solid-js";
import type { Provenance } from "~/api/client";
import { formatDateTime } from "~/utils/format";
import { isGitHubUrl, gitHubCommitUrl } from "~/utils/oci";
import {
    ShieldIcon,
    GitHubIcon,
    ExternalLinkIcon,
} from "./metadata/OciIcons";
import { LinkedField } from "./metadata/LinkedField";

export default function ProvenanceCard(props: { provenance: Provenance }) {
    // eslint-disable-next-line solid/reactivity
    const p = props.provenance;

    const badge = () => {
        if (p.verified === true)
            return <span class="badge badge-success">Verified</span>;
        if (p.verified === false)
            return (
                <span class="badge badge-danger">Verification failed</span>
            );
        if (p.signaturePresent || p.attestationPresent)
            return <span class="badge badge-warning">Signed</span>;
        return <span class="badge">Unsigned</span>;
    };

    const sourceIcon = () =>
        p.sourceUri !== undefined && isGitHubUrl(p.sourceUri)
            ? GitHubIcon
            : undefined;

    const commitUrl = () => {
        if (p.sourceUri === undefined || p.sourceCommit === undefined)
            return null;
        return gitHubCommitUrl(p.sourceUri, p.sourceCommit);
    };

    const rekorUrl = () =>
        p.rekorLogIndex !== undefined
            ? `https://search.sigstore.dev/?logIndex=${p.rekorLogIndex}`
            : null;

    return (
        <div class="card mb-4">
            <div class="card-header">
                <h3
                    style={{
                        display: "flex",
                        "align-items": "center",
                        gap: "0.5rem",
                    }}
                >
                    <ShieldIcon />
                    Provenance
                </h3>
                {badge()}
            </div>

            <div class="detail-grid">
                {/* Signer fingerprint */}
                <Show when={p.signerFingerprint}>
                    {(fp) => (
                        <div class="detail-field">
                            <span class="detail-label">Signer</span>
                            <span class="detail-value font-mono text-sm">
                                {fp().substring(0, 16)}
                            </span>
                        </div>
                    )}
                </Show>

                {/* Source repository */}
                <Show when={p.sourceUri}>
                    {(src) => (
                        <LinkedField
                            label="Source"
                            url={src()}
                            icon={sourceIcon()}
                        />
                    )}
                </Show>

                {/* Commit */}
                <Show when={p.sourceCommit}>
                    {(commit) => (
                        <div class="detail-field">
                            <span class="detail-label">Commit</span>
                            <span class="detail-value font-mono text-sm">
                                <Show
                                    when={commitUrl()}
                                    fallback={commit().substring(0, 12)}
                                >
                                    {(url) => (
                                        <a
                                            href={url()}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            class="purl-link"
                                        >
                                            <GitHubIcon />
                                            {commit().substring(0, 12)}
                                            <ExternalLinkIcon />
                                        </a>
                                    )}
                                </Show>
                            </span>
                        </div>
                    )}
                </Show>

                {/* Build time */}
                <Show when={p.buildStartedOn}>
                    {(ts) => (
                        <div class="detail-field">
                            <span class="detail-label">Built</span>
                            <span class="detail-value">
                                {formatDateTime(ts())}
                            </span>
                        </div>
                    )}
                </Show>

                {/* Builder */}
                <Show when={p.builderId}>
                    <div class="detail-field">
                        <span class="detail-label">Builder</span>
                        <span class="detail-value">{p.builderId}</span>
                    </div>
                </Show>

                {/* Predicate type */}
                <Show when={p.predicateType}>
                    <div class="detail-field">
                        <span class="detail-label">Predicate</span>
                        <span class="detail-value">{p.predicateType}</span>
                    </div>
                </Show>

                {/* Rekor transparency log */}
                <Show when={rekorUrl()}>
                    {(url) => (
                        <LinkedField
                            label="Rekor"
                            url={url()}
                            display={`#${p.rekorLogIndex}`}
                            icon={() => <ExternalLinkIcon />}
                        />
                    )}
                </Show>
            </div>
        </div>
    );
}
