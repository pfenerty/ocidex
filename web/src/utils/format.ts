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
    if (version !== undefined) {
        return `${version} · ${date}`;
    }
    if (sbom.componentCount !== undefined && sbom.componentCount > 0) {
        return `${date} · ${sbom.componentCount} components`;
    }
    return `${shortId(sbom.id)} · ${date}`;
}

/**
 * Richer label for SBOM picker dropdowns, disambiguating multi-arch builds.
 *
 *  "24.04 · amd64 · built Jan 15, 2025, 3:42 PM"
 *  "24.04 · amd64 · ingested Jan 15, 2025"
 *  "24.04 · Jan 15, 2025"
 *  "Jan 15, 2025, 3:42 PM · 342 components"
 */
export function sbomPickerLabel(sbom: SBOMSummary): string {
    const version = sbom.subjectVersion ?? sbom.imageVersion;
    const ingested = formatDate(sbom.createdAt);

    if (version !== undefined) {
        const built = sbom.buildDate !== undefined ? `built ${formatDateTime(sbom.buildDate)}` : `ingested ${ingested}`;
        return [version, sbom.architecture, sbom.flavor, built].filter(Boolean).join(" · ");
    }

    const dt = sbom.buildDate !== undefined ? formatDateTime(sbom.buildDate) : ingested;
    const comps = sbom.componentCount !== undefined && sbom.componentCount > 0 ? `${sbom.componentCount} components` : undefined;
    return [dt, comps].filter(Boolean).join(" · ");
}

/**
 * Shorter variant for space-constrained contexts (table cells, dropdowns).
 *
 *  "24.04"  or  "Jan 15, 2025"  or  "a1b2c3d4"
 */
export function sbomShortLabel(sbom: SBOMSummary): string {
    const version = sbom.subjectVersion ?? sbom.imageVersion;
    if (version !== undefined) return version;
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
    const comps =
        sbom.componentCount !== undefined
            ? `${sbom.componentCount} component${sbom.componentCount !== 1 ? "s" : ""}`
            : null;
    const spec = `CycloneDX ${sbom.specVersion}`;

    const version = sbom.subjectVersion ?? sbom.imageVersion;
    if (version !== undefined) {
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
    return artifact.group !== undefined
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
    let display =
        component.group !== undefined
            ? `${component.group}/${component.name}`
            : component.name;
    if (component.version !== undefined) {
        display += `@${component.version}`;
    }
    return display;
}

/**
 * meaningfulDate returns the timestamp unless it carries no information
 * (ocidex-5692): unparseable, Go's zero time, or the Unix epoch. The epoch is
 * the common one: reproducible builds pin SOURCE_DATE_EPOCH=0, so an image's
 * build date is 1970-01-01T00:00:00Z, which US time zones rendered as
 * "Dec 31, 1969". Anything before 1971 is treated the same way; no SBOM'd
 * software was built then.
 */
export function meaningfulDate(iso: string | undefined): string | undefined {
    if (iso === undefined || iso === "") return undefined;
    const t = new Date(iso).getTime();
    if (Number.isNaN(t) || t < Date.UTC(1971, 0, 1)) return undefined;
    return iso;
}

/**
 * buildTime is when a build happened, for ordering and display: its build date
 * when that means something, else when OCIDex ingested it.
 */
export function buildTime(x: { buildDate?: string; createdAt: string }): string {
    return meaningfulDate(x.buildDate) ?? x.createdAt;
}

/**
 * Format a date string as a short human-readable date.
 *
 *  "Jan 15, 2025"
 */
export function formatDate(iso: string): string {
    if (meaningfulDate(iso) === undefined) return "—";
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
    if (meaningfulDate(iso) === undefined) return "—";
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
    if (meaningfulDate(iso) === undefined) return "—";
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
 *  plural(3, "component")               → "3 components"
 *  plural(1, "SBOM")                    → "1 SBOM"
 *  plural(2, "registry", "registries")  → "2 registries"
 *
 * `plural` names the thing being counted, so it has to handle the words this
 * app actually counts — "registry" and "repository" among them, neither of
 * which takes a bare "s". The explicit form is opt-in: without it the -s rule
 * silently produces "2 registrys".
 */
export function plural(count: number, word: string, pluralWord?: string): string {
    if (count === 1) return `${count} ${word}`;
    return `${count} ${pluralWord ?? `${word}s`}`;
}

/**
 * Type guard for non-null, non-undefined, non-empty strings.
 *
 * Replaces the verbose `s !== undefined && s !== ""` pattern.
 *
 *  hasText(undefined) → false
 *  hasText(null)      → false
 *  hasText("")        → false
 *  hasText("hello")   → true
 */
export function hasText(s: string | null | undefined): s is string {
    return s !== undefined && s !== null && s !== "";
}
