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
    "weak-copyleft": {
        bg: "var(--color-warning)",
        label: "Weak Copyleft",
        badge: "badge-warning",
    },
    copyleft: {
        bg: "var(--color-danger)",
        label: "Copyleft",
        badge: "badge-danger",
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
