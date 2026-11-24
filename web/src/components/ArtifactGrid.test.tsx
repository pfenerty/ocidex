// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { Router, Route } from "@solidjs/router";
import { render } from "@solidjs/testing-library";
import { ArtifactGrid } from "./ArtifactGrid";
import type { ArtifactSummary } from "~/api/client";

const artifact = (n: number, name: string): ArtifactSummary =>
    ({ id: `a${n}`, type: "container", name, sbomCount: 1, sufficientSbomCount: 1, signingStatus: "unsigned", entryNumber: n, vulnMatched: false });

function renderGrid(props: Parameters<typeof ArtifactGrid>[0]) {
    return render(() => (
        <Router>
            <Route path="*" component={() => <ArtifactGrid {...props} />} />
        </Router>
    ));
}

describe("ArtifactGrid", () => {
    it("orders caught artifacts by entry number", () => {
        const { container } = renderGrid({ artifacts: [artifact(3, "ghcr.io/x/c"), artifact(1, "ghcr.io/x/a")] });
        const numbers = [...container.querySelectorAll(".artifact-slot-number")].map((n) => n.textContent);
        expect(numbers).toEqual(["\u2116 001", "\u2116 003"]);
    });

    it("adds a silhouette slot per seen-only image, linking to its cluster's gaps", () => {
        const { container } = renderGrid({
            artifacts: [artifact(1, "ghcr.io/x/a")],
            seenOnly: [{ clusterId: "k1", imageRef: "ghcr.io/acme/billing-worker:1.2@sha256:abc", imageDigest: "sha256:abc" }],
        });
        const slot = container.querySelector(".artifact-slot.seen-only");
        expect(slot?.querySelector(".artifact-slot-name")?.textContent).toBe("billing-worker");
        expect(slot?.querySelector("a")?.getAttribute("href")).toBe("/clusters/k1?tab=gaps");
        expect(slot?.querySelector(".artifact-slot-number")?.textContent).toBe("not caught");
    });

    // Sprites scale to each artifact's own history, so on their own a row of
    // them reads as identical glyphs.
    it("says each card's latest critical count and tints its newest bar when there are any", () => {
        const withCrit: ArtifactSummary = {
            ...artifact(1, "ghcr.io/x/a"),
            vulns: { critical: 4, high: 0, medium: 0, low: 0, unknown: 0, total: 4 },
            criticalHistory: [
                { versionKey: "2.0.0", critical: 4 },
                { versionKey: "1.0.0", critical: 9 },
            ],
        };
        const clean: ArtifactSummary = {
            ...artifact(2, "ghcr.io/x/b"),
            vulns: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0, total: 1 },
            criticalHistory: [{ versionKey: "1.0.0", critical: 0 }],
        };
        // Scanned with no findings: no summary, but matched, so a zero.
        const none: ArtifactSummary = { ...artifact(4, "ghcr.io/x/d"), vulnMatched: true };
        const { container } = renderGrid({ artifacts: [withCrit, clean, artifact(3, "ghcr.io/x/c"), none] });
        const slots = [...container.querySelectorAll(".artifact-slot")];
        expect(slots.map((s) => s.querySelector(".artifact-slot-crit")?.textContent)).toEqual([
            "4 critical",
            "0 critical",
            undefined,
            "0 critical",
        ]);
        expect(slots[0].querySelectorAll(".sprite-bar-critical")).toHaveLength(1);
        expect(slots[1].querySelectorAll(".sprite-bar-critical")).toHaveLength(0);
    });
});
