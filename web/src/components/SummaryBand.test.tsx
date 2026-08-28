// @vitest-environment happy-dom
import { describe, it, expect, afterEach } from "vitest";
import { render, cleanup } from "@solidjs/testing-library";
import SummaryBand from "./SummaryBand";

afterEach(cleanup);
import type { Provenance, VulnSummary } from "~/api/client";

function renderBand(provenance: Provenance | undefined, signingStatus: string | undefined) {
    const { container } = render(() => (
        <SummaryBand
            provenance={provenance}
            signingStatus={signingStatus}
            metadata={undefined}
            git={undefined}
            packageCount={0}
            ecosystems={[]}
            vulns={undefined}
            specVersion="1.6"
            ingestedAt="2026-07-31T00:00:00Z"
            active="provenance"
            onSelect={() => undefined}
        />
    ));
    const sub = container.querySelector(".tile-sub");
    if (sub === null) throw new Error("provenance tile has no sub-line");
    return { tile: container.textContent, sub: sub.textContent };
}

describe("SummaryBand provenance sub-line", () => {
    // Regression: the sub-line was the fallback for a missing SLSA builder id,
    // but printed the string "no signature". An SBOM with a cosign signature
    // and no build metadata therefore rendered "Signed / no signature" —
    // the tile contradicting itself.
    it("never claims there is no signature when one is present", () => {
        const { tile, sub } = renderBand(
            { signaturePresent: true, attestationPresent: true },
            "signed",
        );
        expect(tile).toContain("Signed");
        expect(tile).not.toContain("no signature");
        expect(sub).toBe("cosign signature · SLSA attestation");
    });

    it("names just the facts that are present", () => {
        expect(renderBand({ signaturePresent: true, attestationPresent: false }, "signed").sub)
            .toBe("cosign signature");
        expect(renderBand({ signaturePresent: false, attestationPresent: true }, "signed").sub)
            .toBe("SLSA attestation");
    });

    it("prefers the builder when the attestation carries one", () => {
        expect(
            renderBand(
                {
                    signaturePresent: true,
                    attestationPresent: true,
                    builderId: "https://tekton.dev/chains/v2",
                },
                "verified",
            ).sub,
        ).toBe("Tekton Chains");
    });

    it("reports absent signing material honestly", () => {
        expect(renderBand({ signaturePresent: false, attestationPresent: false }, "unsigned").sub)
            .toBe("no signing material");
    });

    it("renders an em dash when there is no provenance at all", () => {
        expect(renderBand(undefined, undefined).sub).toBe("—");
    });
});

// ── Vulnerability tile (ocidex-ag4q.15) ──────────────────────────────────────

function renderVulnTile(vulns: VulnSummary | undefined) {
    const { container } = render(() => (
        <SummaryBand
            provenance={undefined}
            signingStatus={undefined}
            metadata={undefined}
            git={undefined}
            packageCount={0}
            ecosystems={[]}
            vulns={vulns}
            specVersion="1.6"
            ingestedAt="2026-07-31T00:00:00Z"
            active="provenance"
            onSelect={() => undefined}
        />
    ));
    const tile = [...container.querySelectorAll(".tile")].find((t) =>
        t.textContent.includes("Vulnerabilities"),
    );
    if (tile === undefined) throw new Error("no vulnerability tile in the band");
    return { tile, container };
}

const summary = (over: Partial<VulnSummary>): VulnSummary => ({
    critical: 0, high: 0, medium: 0, low: 0, unknown: 0, total: 0, ...over,
});

describe("SummaryBand vulnerability tile", () => {
    it("distinguishes never-scanned from clean", () => {
        // An SBOM with no scan must not read as having no vulnerabilities —
        // the same distinction ADR-044 insists on for unmatched workloads.
        expect(renderVulnTile(undefined).tile.textContent).toContain("not scanned");
        expect(renderVulnTile(undefined).tile.textContent).not.toContain("no known");
    });

    it("says so explicitly when a scan found nothing", () => {
        expect(renderVulnTile(summary({})).tile.textContent).toContain("no known vulnerabilities");
    });

    it("leads with the worst severity present, not the total alone", () => {
        // "1 critical" and "40 low" must not render as the same shape.
        const { tile } = renderVulnTile(summary({ critical: 1, low: 39, total: 40 }));
        expect(tile.textContent).toContain("40");
        expect(tile.textContent).toContain("1 critical");
        expect(tile.querySelector(".sev-critical")).not.toBeNull();
    });

    it("is a button, because the page has a vulnerabilities tab to reach", () => {
        // The inverse of what this asserted before ocidex-unn8.5. StatBand
        // derives the element from whether the tile carries an id, so a tile
        // that renders as a DIV here is one whose destination has gone missing —
        // it would still look like a control and still do nothing.
        expect(renderVulnTile(summary({ high: 2, total: 2 })).tile.tagName).toBe("BUTTON");
    });
});
