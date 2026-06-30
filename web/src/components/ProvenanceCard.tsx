import "~/components/DetailSection.css";
import "./ProvenanceCard.css";
import { Show, For } from "solid-js";
import { Check, X } from "lucide-solid";
import type { Provenance } from "~/api/client";
import { formatDateTime } from "~/utils/format";
import { isGitHubUrl, gitHubCommitUrl } from "~/utils/oci";
import { trustStatus, trustBadgeClass } from "~/utils/trust";
import { ShieldIcon, GitHubIcon, ExternalLinkIcon } from "./metadata/OciIcons";
import { LinkedField } from "./metadata/LinkedField";

// FactPill renders a present/absent trust fact (e.g. "cosign signature ✓").
function FactPill(props: { present: boolean; label: string }) {
    return (
        <span class={`fact-pill ${props.present ? "fact-present" : "fact-absent"}`}>
            {props.present ? <Check size={14} /> : <X size={14} />}
            {props.label}
        </span>
    );
}

export default function ProvenanceCard(props: { provenance: Provenance }) {
    // eslint-disable-next-line solid/reactivity
    const p = props.provenance;

    const trust = () => trustStatus(p);

    const commitUrl = () => {
        if (p.sourceUri === undefined || p.sourceCommit === undefined) return null;
        return gitHubCommitUrl(p.sourceUri, p.sourceCommit);
    };

    // Prefer the precise Rekor entry by UUID; fall back to a log-index search.
    const rekorUrl = () => {
        if (p.rekorUuid !== undefined && p.rekorUuid !== "")
            return `https://search.sigstore.dev/?uuid=${p.rekorUuid}`;
        if (p.rekorLogIndex !== undefined && p.rekorLogIndex !== 0)
            return `https://search.sigstore.dev/?logIndex=${p.rekorLogIndex}`;
        return null;
    };

    return (
        <div class="card mb-4">
            <div class="card-header">
                <h3 style={{ display: "flex", "align-items": "center", gap: "0.5rem" }}>
                    <ShieldIcon />
                    Provenance
                </h3>
                <Show when={trust()}>
                    {(t) => <span class={trustBadgeClass(t().variant)}>{t().label}</span>}
                </Show>
            </div>

            {/* Distinct trust facts */}
            <div class="fact-row">
                <FactPill present={p.signaturePresent === true} label="cosign signature" />
                <FactPill present={p.attestationPresent === true} label="SLSA attestation" />
            </div>

            <div class="detail-grid">
                {/* Verification basis */}
                <Show when={p.verified !== undefined}>
                    <div class="detail-field">
                        <span class="detail-label">Verification</span>
                        <span class="detail-value">
                            {p.verified === true
                                ? "Verified against trusted key"
                                : "Verification failed"}
                        </span>
                    </div>
                </Show>

                {/* Signer key fingerprint */}
                <Show when={p.signerFingerprint}>
                    {(fp) => (
                        <div class="detail-field">
                            <span class="detail-label">Signer key</span>
                            <span class="detail-value font-mono text-sm">{fp()}</span>
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

                {/* Build time */}
                <Show when={p.buildStartedOn}>
                    {(ts) => (
                        <div class="detail-field">
                            <span class="detail-label">Built</span>
                            <span class="detail-value">{formatDateTime(ts())}</span>
                        </div>
                    )}
                </Show>

                {/* Source repository (conditional) */}
                <Show when={p.sourceUri}>
                    {(src) => (
                        <LinkedField
                            label="Source"
                            url={src()}
                            icon={isGitHubUrl(src()) ? GitHubIcon : undefined}
                        />
                    )}
                </Show>

                {/* Commit (conditional) */}
                <Show when={p.sourceCommit}>
                    {(commit) => (
                        <div class="detail-field">
                            <span class="detail-label">Commit</span>
                            <span class="detail-value font-mono text-sm">
                                <Show when={commitUrl()} fallback={commit().substring(0, 12)}>
                                    {(url) => (
                                        <a href={url()} target="_blank" rel="noopener noreferrer" class="purl-link">
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

                {/* Rekor transparency log (conditional — absent for key-based signing) */}
                <Show when={rekorUrl()}>
                    {(url) => (
                        <LinkedField
                            label="Rekor"
                            url={url()}
                            display={p.rekorLogIndex !== undefined && p.rekorLogIndex !== 0 ? `#${p.rekorLogIndex}` : "entry"}
                            icon={() => <ExternalLinkIcon />}
                        />
                    )}
                </Show>
            </div>

            {/* Subjects covered by the attestation (collapsible) */}
            <Show when={p.subjects !== undefined && p.subjects.length > 0 ? p.subjects : undefined}>
                {(subjects) => (
                    <details class="mt-4">
                        <summary class="text-muted text-sm" style={{ cursor: "pointer" }}>
                            Subjects ({subjects().length})
                        </summary>
                        <ul class="subjects-list">
                            <For each={subjects()}>
                                {(s) => <li class="font-mono text-sm">{s}</li>}
                            </For>
                        </ul>
                    </details>
                )}
            </Show>
        </div>
    );
}
