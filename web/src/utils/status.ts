/**
 * One status vocabulary (ocidex-iz0r.4).
 *
 * Every state the UI reports (does an image have an SBOM, has it been scanned,
 * is the agent reporting) is defined here once: its words, its tone, and what
 * it means. The legend, the row chip and the filter read the same entry, so they
 * cannot disagree. Before this the cluster page's coverage legend said "no SBOM"
 * in amber while every row beneath it said it in red, and "never scanned" was
 * spelled five ways ("not scanned", "not assessed", "none known", an em dash,
 * a row of dim zeros), some of which also meant "clean".
 *
 * Tones, never hues. Each maps to a token in index.css (.status-<tone>,
 * .tone-fill-<tone>):
 *   ok      the good state
 *   warn    a gap the user can close
 *   bad     a failure or a trust problem
 *   off     no information, or deliberately inactive
 *   unknown never assessed: drawn hatched, so it can't be mistaken for "0"
 */
import type { WorkloadMatchState } from "~/api/client";

export type Tone = "ok" | "warn" | "bad" | "off" | "unknown";

export interface Status {
    label: string;
    tone: Tone;
    /** What the state means, for the chip's tooltip. */
    title: string;
}

/** How a running workload relates to the catalog (ADR-044). */
export const MATCH_STATUS: Record<WorkloadMatchState, Status> = {
    exact: {
        label: "Matched",
        tone: "ok",
        title: "The running digest matches an ingested SBOM exactly",
    },
    index: {
        label: "Matched (index)",
        tone: "ok",
        title: "The runtime reported the multi-arch index digest; the SBOM shown is for one platform of that index",
    },
    unknown: {
        label: "No SBOM",
        tone: "warn",
        title: "A valid digest that matches nothing ingested. Ingesting the image closes this gap",
    },
    unresolvable: {
        label: "No digest",
        tone: "off",
        title: "The runtime reported no registry-addressable digest, so this image cannot be matched at all",
    },
};

/**
 * Whether vulnerability data exists. "Has findings" is not a status here: it
 * renders as the severity breakdown itself.
 */
export const VULN_DATA_STATUS = {
    clean: {
        label: "0 known",
        tone: "ok",
        title: "Scanned, and no known vulnerability matches",
    },
    unscanned: {
        label: "Not scanned",
        tone: "unknown",
        title: "No findings are recorded, which may mean it was never scanned. Its exposure is unknown, not zero",
    },
} as const satisfies Record<string, Status>;

export type AgentHealthState = "healthy" | "stale" | "erroring" | "never_reported" | "paused";

/** A cluster agent's reporting state. The relative time is appended by the caller. */
export const AGENT_HEALTH_STATUS: Record<AgentHealthState, Status> = {
    healthy: { label: "Reporting", tone: "ok", title: "The agent's last snapshot arrived on schedule" },
    stale: { label: "Stale", tone: "warn", title: "The inventory below may not be what is running now" },
    erroring: { label: "Erroring", tone: "bad", title: "The agent is pushing and being refused" },
    never_reported: {
        label: "Never reported",
        tone: "warn",
        title: "No agent has ever pushed a snapshot for this cluster",
    },
    paused: { label: "Paused", tone: "off", title: "Paused: snapshots are refused" },
};
