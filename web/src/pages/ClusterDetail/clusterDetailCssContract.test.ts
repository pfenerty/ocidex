import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * ClusterDetail owns two rules that override a shared component's defaults, and
 * both are the kind that fail silently: nothing throws when an override stops
 * matching, the page just goes subtly wrong in a viewport nobody re-opens.
 *
 * Both were checked in a browser against the seeded rig (ocidex-ag4q.60) before
 * being written down here. This file is what keeps them checked.
 */
const css = readFileSync(join(__dirname, "ClusterDetail.css"), "utf-8");

/** The body of the rule whose selector list contains `selector`. */
function rule(selector: string, within = css): string {
    const i = within.indexOf(selector);
    if (i === -1) throw new Error(`no rule for ${selector}`);
    const open = within.indexOf("{", i);
    const close = within.indexOf("}", open);
    return within.slice(open + 1, close);
}

describe("ClusterDetail.css overrides", () => {
    // The coverage legend's labels are remedies ("no SBOM · ingest to fix");
    // they must wrap onto the next line rather than run off a narrow screen.
    it("lets the coverage legend wrap", () => {
        expect(rule(".coverage-legend {")).toMatch(/flex-wrap:\s*wrap/);
    });

    // ADR-044 K5: a non-zero gap must not read like a clean count.
    it("colours a non-zero gap's count", () => {
        expect(rule(".coverage-segment.gap strong")).toMatch(/color:\s*var\(--color-warning\)/);
    });

    // DataTable's card stack undoes `.text-right` with `text-align: left`,
    // which cannot reach `align-items` on a flex column — so the Workloads
    // value stayed pinned to the right edge, a card's width away from its own
    // label (ocidex-ag4q.61).
    it("un-pins the right-aligned inventory cell inside a card", () => {
        const start = css.indexOf("@media (max-width: 768px)");
        expect(start).toBeGreaterThan(-1);
        const body = rule(".table-mobile-cards .inventory-cell-right", css.slice(start));
        expect(body).toMatch(/align-items:\s*flex-start/);
    });
});
