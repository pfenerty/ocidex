import { Shield, ShieldAlert, ShieldCheck, ShieldOff, ShieldX } from "lucide-solid";
import type { LucideIcon } from "lucide-solid";
import type { BadgeVariant } from "~/components/ui/Badge";

export type TrustVariant = "info" | "warning" | "danger" | "neutral";

// TrustIcon is the lucide-solid component used to render a status.
export type TrustIcon = LucideIcon;

export interface TrustStatus {
    label: string;
    variant: TrustVariant;
    icon: TrustIcon;
    // description is the badge tooltip. It names *why* the status holds —
    // "Signed" vs "Verified" is otherwise indistinguishable to a user, since
    // the difference is a registry trust-anchor setting, not a property of the
    // artifact.
    description: string;
}

// STATUS_INFO is the single source of truth for how the five signing statuses
// (ADR-037) are presented. The colour axis is deliberately green-free:
//
//   blue   — OCIDex affirmed something (verified)
//   grey   — OCIDex has no information (signed, unsigned)
//   amber  — availability problem (artifact_missing)
//   red    — trust problem (verification_failed)
//
// `signed` in particular must not read as a warning: per ADR-037 it means "no
// cryptographic check was performed", which is an OCIDex configuration gap,
// not a defect in the artifact.
const STATUS_INFO: Record<string, TrustStatus> = {
    verified: {
        label: "Verified",
        variant: "info",
        icon: ShieldCheck,
        description:
            "OCIDex cryptographically verified this artifact's signature against the registry's configured trust anchor.",
    },
    signed: {
        label: "Signed",
        variant: "neutral",
        icon: Shield,
        description:
            "Signing material was found, but this registry has no trust anchor configured, so OCIDex did not verify it. Set a verification mode on the registry to upgrade this to Verified.",
    },
    unsigned: {
        label: "Unsigned",
        variant: "neutral",
        icon: ShieldOff,
        description: "No signature or attestation was found for this artifact in the registry.",
    },
    artifact_missing: {
        label: "Artifact missing",
        variant: "warning",
        icon: ShieldAlert,
        description:
            "The artifact's digest no longer resolves in the registry, so its provenance can't be re-checked.",
    },
    verification_failed: {
        label: "Verification failed",
        variant: "danger",
        icon: ShieldX,
        description:
            "A cryptographic check ran and did not pass, or a signing payload was present but unreadable. Treat this artifact as untrusted.",
    },
};

// trustStatus maps a server-computed signing status to the headline trust
// signal. Returns null when there is no status to summarize.
export function trustStatus(status: string | undefined): TrustStatus | null {
    if (status === undefined) return null;
    return STATUS_INFO[status] ?? null;
}

// signingStatusLabel returns the display label for a signing status,
// falling back to the raw status string for unrecognized values.
export function signingStatusLabel(status: string): string {
    return trustStatus(status)?.label ?? status;
}

// trustBadgeVariant maps a trust variant onto the shared Badge component's
// variant. Kept alongside trustBadgeClass so the class-string and <Badge>
// render paths can never disagree about a status's colour.
export function trustBadgeVariant(variant: TrustVariant): BadgeVariant {
    switch (variant) {
        case "info": return "primary";
        case "danger": return "danger";
        case "warning": return "warning";
        default: return "default";
    }
}

// trustBadgeClass maps a trust variant to the shared badge CSS class.
export function trustBadgeClass(variant: TrustVariant): string {
    const badgeVariant = trustBadgeVariant(variant);
    return badgeVariant === "default" ? "badge" : `badge badge-${badgeVariant}`;
}

// signingStatuses lists every known status in escalating order of concern,
// for rendering legends and tests without duplicating the table.
export const signingStatuses = [
    "verified",
    "signed",
    "unsigned",
    "artifact_missing",
    "verification_failed",
] as const;

const DRIFT_REASON_LABELS: Record<string, string> = {
    trust_config_changed: "the registry's trust configuration changed",
    artifact_missing: "the artifact was removed from the registry",
    reverification_failed: "re-verification failed",
};

// driftReasonLabel returns a human-readable explanation for a provenance
// drift reason code, falling back to the raw code for unrecognized values.
export function driftReasonLabel(reason: string): string {
    return DRIFT_REASON_LABELS[reason] ?? reason;
}
