import "~/components/DetailSection.css";
import "./ProvenanceCard.css";
import { Show, For } from "solid-js";
import { Check, X } from "lucide-solid";
import type { Provenance, ProvenanceDriftSummary } from "~/api/client";
import { formatDateTime } from "~/utils/format";
import { isGitHubUrl, gitHubCommitUrl } from "~/utils/oci";
import { trustStatus, trustBadgeClass, signingStatusLabel, driftReasonLabel } from "~/utils/trust";
import { ShieldIcon, GitHubIcon, ExternalLinkIcon } from "./metadata/OciIcons";
import { LinkedField } from "./metadata/LinkedField";
import { Card, CardHeader } from "~/components/ui";

// FactPill renders a present/absent trust fact (e.g. "cosign signature ✓").
function FactPill(props: { present: boolean; label: string }) {
    return (
        <span class={`fact-pill ${props.present ? "fact-present" : "fact-absent"}`}>
            {props.present ? <Check size={14} /> : <X size={14} />}
            {props.label}
        </span>
    );
}

export default function ProvenanceCard(props: {
    provenance: Provenance;
    signingStatus: string;
    drift?: ProvenanceDriftSummary;
    driftHistory?: ProvenanceDriftSummary[];
}) {
    // eslint-disable-next-line solid/reactivity
    const p = props.provenance;

    const trust = () => trustStatus(props.signingStatus);

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
        <Card class="mb-4">
            <CardHeader
                title={
                    <span class="title-inline">
                        <ShieldIcon />
                        Provenance
                    </span>
                }
                actions={
                    <Show when={trust()}>
                        {(t) => <span class={trustBadgeClass(t().variant)}>{t().label}</span>}
                    </Show>
                }
            />

            <Show when={props.drift}>
                {(d) => (
                    <div class="badge badge-warning" style={{ display: "block", "margin-bottom": "0.75rem" }}>
                        Verification status changed from{" "}
                        <strong>{signingStatusLabel(d().previousStatus)}</strong> to{" "}
                        <strong>{signingStatusLabel(d().newStatus)}</strong> on{" "}
                        {formatDateTime(d().detectedAt)}
                        {" — "}{driftReasonLabel(d().reason)}.
                    </div>
                )}
            </Show>

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
                                ? (p.signerIssuer !== undefined && p.signerIssuer !== ""
                                    ? `Verified — keyless (issuer: ${p.signerIssuer}, identity: ${p.signerIdentity})`
                                    : "Verified against trusted key")
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
                        <summary class="text-muted text-sm cursor-pointer">
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

            {/* Verification history (collapsible) */}
            <Show when={(props.driftHistory?.length ?? 0) > 1 ? props.driftHistory : undefined}>
                {(history) => (
                    <details class="mt-4">
                        <summary class="text-muted text-sm cursor-pointer">
                            History ({history().length})
                        </summary>
                        <table class="table mt-2">
                            <thead>
                                <tr>
                                    <th>Detected</th>
                                    <th>Change</th>
                                    <th>Reason</th>
                                </tr>
                            </thead>
                            <tbody>
                                <For each={history()}>
                                    {(event) => (
                                        <tr>
                                            <td class="text-sm">{formatDateTime(event.detectedAt)}</td>
                                            <td class="text-sm">
                                                {signingStatusLabel(event.previousStatus)} → {signingStatusLabel(event.newStatus)}
                                            </td>
                                            <td class="text-muted text-sm">{driftReasonLabel(event.reason)}</td>
                                        </tr>
                                    )}
                                </For>
                            </tbody>
                        </table>
                    </details>
                )}
            </Show>
        </Card>
    );
}
