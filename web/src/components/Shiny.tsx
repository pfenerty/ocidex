import "./Shiny.css";
import type { JSX } from "solid-js";

/**
 * The mark of an artifact whose latest version has been matched against the
 * vulnerability store and has no known vulnerabilities. Rare by design: it is
 * never shown for an SBOM that has not been matched, since "no findings" and
 * "never scanned" otherwise look the same (ADR-044).
 */
export function Shiny(): JSX.Element {
    return (
        <span class="shiny" title="Matched against the vulnerability store, with no known vulnerabilities in the latest version">
            <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
                <path d="M5 0 L6.1 3.9 L10 5 L6.1 6.1 L5 10 L3.9 6.1 L0 5 L3.9 3.9 Z" fill="currentColor" />
            </svg>
            shiny
        </span>
    );
}

/** True only for a matched SBOM with zero findings. */
export function isShiny(matched: boolean, total: number | undefined): boolean {
    return matched && (total ?? 0) === 0;
}
