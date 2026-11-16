/**
 * Unified license category color/label/badge mapping.
 * Used across ArtifactDetail, Home, and Licenses pages.
 */
export const CATEGORY_COLORS: Partial<
    Record<string, { bg: string; label: string; badge: string }>
> = {
    permissive: {
        bg: "var(--color-success)",
        label: "Permissive",
        badge: "badge-success",
    },
    // Copyleft is an obligation to check, not a failure: the warn tone, never
    // danger red, which belongs to failures and trust problems (ocidex-iz0r.4).
    // Weak copyleft is the same tone at lower strength in bars.
    "weak-copyleft": {
        bg: "color-mix(in srgb, var(--color-warning) 55%, transparent)",
        label: "Weak copyleft",
        badge: "badge-warning",
    },
    copyleft: {
        bg: "var(--color-warning)",
        label: "Copyleft",
        badge: "badge-warning",
    },
    uncategorized: {
        bg: "var(--color-text-dim)",
        label: "Uncategorized",
        badge: "",
    },
    unknown: {
        bg: "var(--color-text-dim)",
        label: "Unknown",
        badge: "",
    },
};
