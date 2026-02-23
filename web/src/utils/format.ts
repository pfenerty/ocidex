import type { SBOMSummary } from "~/api/client";

/**
 * Build a human-friendly label for an SBOM row.
 *
 * Priority:
 *  1. subjectVersion + date  → "24.04 · Jan 15, 2025"
 *  2. date + component count → "Jan 15, 2025 · 342 components"
 *  3. short id + date        → "a1b2c3d4 · Jan 15, 2025"
 */
export function sbomLabel(sbom: SBOMSummary): string {
    const date = formatDate(sbom.createdAt);
    const version = sbom.subjectVersion ?? sbom.imageVersion;
    if (version) {
        return `${version} · ${date}`;
    }
    if (sbom.componentCount) {
        return `${date} · ${sbom.componentCount} components`;
    }
    return `${shortId(sbom.id)} · ${date}`;
}

/**
 * Shorter variant for space-constrained contexts (table cells, dropdowns).
 *
 *  "24.04"  or  "Jan 15, 2025"  or  "a1b2c3d4"
 */
export function sbomShortLabel(sbom: SBOMSummary): string {
    const version = sbom.subjectVersion ?? sbom.imageVersion;
    if (version) return version;
    return formatDate(sbom.createdAt);
}

/**
 * Build a two-line description: primary + secondary context.
 * Returns [primary, secondary].
 *
 *  ["24.04", "Jan 15, 2025 · 342 components"]
 *  ["Jan 15, 2025", "342 components · CycloneDX 1.6"]
 */
export function sbomDescriptionParts(sbom: SBOMSummary): [string, string] {
    const date = formatDate(sbom.createdAt);
    const comps = sbom.componentCount
        ? `${sbom.componentCount} component${sbom.componentCount !== 1 ? "s" : ""}`
        : null;
    const spec = `CycloneDX ${sbom.specVersion}`;

    const version = sbom.subjectVersion ?? sbom.imageVersion;
    if (version) {
        const secondary = [date, comps, spec].filter(Boolean).join(" · ");
        return [version, secondary];
    }

    const secondary = [comps, spec].filter(Boolean).join(" · ");
    return [date, secondary];
}

/**
 * Build an artifact display name from its parts.
 *
 *  "org.example/my-app" or "docker.io/ubuntu"
 */
export function artifactDisplayName(artifact: {
    name: string;
    group?: string;
}): string {
    return artifact.group
        ? `${artifact.group}/${artifact.name}`
        : artifact.name;
}

/**
 * Format a component for display: "group/name@version" or just "name@version".
 */
export function componentDisplayName(component: {
    name: string;
    group?: string;
    version?: string;
}): string {
    let display = component.group
        ? `${component.group}/${component.name}`
        : component.name;
    if (component.version) {
        display += `@${component.version}`;
    }
    return display;
}

/**
 * Format a date string as a short human-readable date.
 *
 *  "Jan 15, 2025"
 */
export function formatDate(iso: string): string {
    return new Date(iso).toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
        year: "numeric",
    });
}

/**
 * Format a date string with time.
 *
 *  "Jan 15, 2025, 3:42 PM"
 */
export function formatDateTime(iso: string): string {
    return new Date(iso).toLocaleString("en-US", {
        month: "short",
        day: "numeric",
        year: "numeric",
        hour: "numeric",
        minute: "2-digit",
    });
}

/**
 * Format a date as relative time ("2 days ago", "3 months ago").
 * Falls back to absolute date for anything older than 1 year.
 */
export function relativeDate(iso: string): string {
    const now = Date.now();
    const then = new Date(iso).getTime();
    const diffMs = now - then;
    const diffSec = Math.floor(diffMs / 1000);
    const diffMin = Math.floor(diffSec / 60);
    const diffHr = Math.floor(diffMin / 60);
    const diffDay = Math.floor(diffHr / 24);
    const diffMonth = Math.floor(diffDay / 30);

    if (diffSec < 60) return "just now";
    if (diffMin < 60) return `${diffMin}m ago`;
    if (diffHr < 24) return `${diffHr}h ago`;
    if (diffDay === 1) return "yesterday";
    if (diffDay < 30) return `${diffDay}d ago`;
    if (diffMonth < 12) return `${diffMonth}mo ago`;
    return formatDate(iso);
}

/**
 * Truncate a SHA256 digest for display.
 *
 *  "sha256:8feb4d8c…" (first 16 hex chars)
 */
export function shortDigest(digest: string): string {
    if (digest.startsWith("sha256:")) {
        return `sha256:${digest.slice(7, 23)}…`;
    }
    return digest.length > 24 ? `${digest.slice(0, 24)}…` : digest;
}

/**
 * Truncate a UUID or other ID to first 8 characters.
 */
export function shortId(id: string): string {
    return id.slice(0, 8);
}

/**
 * Pluralize a word based on count.
 *
 *  plural(3, "component") → "3 components"
 *  plural(1, "SBOM")      → "1 SBOM"
 */
export function plural(count: number, word: string): string {
    return `${count} ${word}${count !== 1 ? "s" : ""}`;
}
