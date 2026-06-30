import type { Provenance } from "~/api/client";

export type TrustVariant = "success" | "warning" | "danger" | "neutral";

export interface TrustStatus {
    label: string;
    variant: TrustVariant;
}

// trustStatus derives the headline trust signal from provenance enrichment.
// Returns null when there is no provenance data to summarize.
export function trustStatus(p: Provenance | undefined): TrustStatus | null {
    if (p === undefined) return null;
    if (p.verified === true) return { label: "Verified", variant: "success" };
    if (p.verified === false) return { label: "Verification failed", variant: "danger" };
    if (p.signaturePresent === true || p.attestationPresent === true)
        return { label: "Signed", variant: "warning" };
    return { label: "Unsigned", variant: "neutral" };
}

// trustBadgeClass maps a trust variant to the shared badge CSS class.
export function trustBadgeClass(variant: TrustVariant): string {
    switch (variant) {
        case "success": return "badge badge-success";
        case "danger":  return "badge badge-danger";
        case "warning": return "badge badge-warning";
        default:        return "badge";
    }
}
