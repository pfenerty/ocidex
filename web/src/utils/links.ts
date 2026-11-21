/**
 * The public documentation site (ADR-0057). It documents the latest release; the
 * preview of unreleased work is under /next/.
 */
export const DOCS_URL = "https://docs.ocidex.app/";

const SAFE_SCHEMES = new Set(["http:", "https:", "mailto:"]);

/**
 * safeHref returns url if it is an absolute http(s) or mailto URL, and undefined
 * otherwise. Every link whose target comes from an SBOM, an image label or an
 * advisory goes through it: those strings are written by whoever built the image,
 * and a `javascript:` or `data:` URL in an href runs script on click wherever the
 * CSP doesn't stop it (dev, compose, a custom ingress).
 */
export function safeHref(url: string | null | undefined): string | undefined {
    if (url === null || url === undefined) return undefined;
    try {
        // No base: a relative or scheme-less string throws and is refused.
        return SAFE_SCHEMES.has(new URL(url.trim()).protocol) ? url.trim() : undefined;
    } catch {
        return undefined;
    }
}
