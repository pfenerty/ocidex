// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { render } from "@solidjs/testing-library";
import SummaryBand from "./SummaryBand";
import type { Provenance } from "~/api/client";

function renderBand(provenance: Provenance | undefined, signingStatus: string | undefined) {
    const { container } = render(() => (
        <SummaryBand
            provenance={provenance}
            signingStatus={signingStatus}
            metadata={undefined}
            git={undefined}
            packageCount={0}
            ecosystems={[]}
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
