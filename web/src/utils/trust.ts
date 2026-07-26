export type TrustVariant = "success" | "warning" | "danger" | "neutral";

export interface TrustStatus {
    label: string;
    variant: TrustVariant;
}

const STATUS_INFO: Record<string, TrustStatus> = {
    artifact_missing: { label: "Artifact missing", variant: "danger" },
    verified: { label: "Verified", variant: "success" },
    verification_failed: { label: "Verification failed", variant: "danger" },
    signed: { label: "Signed", variant: "warning" },
    unsigned: { label: "Unsigned", variant: "neutral" },
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

// trustBadgeClass maps a trust variant to the shared badge CSS class.
export function trustBadgeClass(variant: TrustVariant): string {
    switch (variant) {
        case "success": return "badge badge-success";
        case "danger":  return "badge badge-danger";
        case "warning": return "badge badge-warning";
        default:        return "badge";
    }
}
