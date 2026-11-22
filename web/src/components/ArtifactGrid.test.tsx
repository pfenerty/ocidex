// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { Router, Route } from "@solidjs/router";
import { render } from "@solidjs/testing-library";
import { ArtifactGrid } from "./ArtifactGrid";
import type { ArtifactSummary } from "~/api/client";

const artifact = (n: number, name: string): ArtifactSummary =>
    ({ id: `a${n}`, type: "container", name, sbomCount: 1, sufficientSbomCount: 1, signingStatus: "unsigned", entryNumber: n });

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
});
