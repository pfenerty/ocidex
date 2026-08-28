// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { render } from "@solidjs/testing-library";
import ProvenanceCard from "./ProvenanceCard";
import type { Provenance } from "~/api/client";

function makeProvenance(overrides: Partial<Provenance> = {}): Provenance {
    return { signaturePresent: true, attestationPresent: false, ...overrides };
}

function renderCard(p: Provenance, signingStatus: string) {
    return render(() => <ProvenanceCard provenance={p} signingStatus={signingStatus} />);
}

// The trust badge in the header repeats the status text, so assertions read the
// detail grid by label rather than searching the whole card.
function fieldValue(container: HTMLElement, label: string): string | null {
    const field = [...container.querySelectorAll(".detail-field")].find(
        (f) => f.querySelector(".detail-label")?.textContent === label,
    );
    return field?.querySelector(".detail-value")?.textContent ?? null;
}

// factPill returns the pill whose label starts with `label`, so a test can
// assert on its state class rather than on the whole fact row.
function factPill(container: HTMLElement, label: string): HTMLElement | undefined {
    return [...container.querySelectorAll<HTMLElement>(".fact-pill")].find((el) =>
        el.textContent.includes(label),
    );
}

// ocidex-vopn: the pill rendered presence only, so a signature cosign had
// rejected got the same green check as one that passed — directly above a red
// "Verification failed" badge.
describe("ProvenanceCard trust fact pills", () => {
    it("marks a rejected signature as rejected, not present", () => {
        const { container } = renderCard(
            makeProvenance({ verified: false, verificationError: "signature: no matching identities" }),
            "verification_failed",
        );

        const pill = factPill(container, "cosign signature");
        expect(pill?.className).toContain("fact-rejected");
        expect(pill?.className).not.toContain("fact-present");
        // Not colour-only: the verdict is in the text too.
        expect(pill?.textContent).toContain("rejected");
    });

    it("marks a verified signature as verified", () => {
        const { container } = renderCard(makeProvenance({ verified: true }), "verified");

        const pill = factPill(container, "cosign signature");
        expect(pill?.className).toContain("fact-verified");
        expect(pill?.textContent).not.toContain("rejected");
    });

    it("leaves a present-but-unchecked signature neutral", () => {
        // No trust anchor configured, so nothing verified it. ADR-037 calls this
        // "no cryptographic check was performed" — it must not read as an
        // endorsement.
        const { container } = renderCard(makeProvenance({}), "signed");

        const pill = factPill(container, "cosign signature");
        expect(pill?.className).toContain("fact-present");
        expect(pill?.className).not.toContain("fact-verified");
    });

    it("leaves an absent fact absent even when the verdict failed", () => {
        const { container } = renderCard(
            makeProvenance({ verified: false, attestationPresent: false }),
            "verification_failed",
        );

        const pill = factPill(container, "SLSA attestation");
        expect(pill?.className).toContain("fact-absent");
        expect(pill?.textContent).not.toContain("rejected");
    });
});

// ocidex-j9qa: a failed verification used to render a bare "Verification failed",
// leaving the cosign error reachable only through the worker's logs.
describe("ProvenanceCard verification reason", () => {
    it("shows the reason when verification ran and rejected", () => {
        const { container } = renderCard(
            makeProvenance({ verified: false, verificationError: "signature: none of the expected identities matched" }),
            "verification_failed",
        );

        expect(fieldValue(container, "Verification")).toBe("Verification failed");
        expect(fieldValue(container, "Reason")).toBe("signature: none of the expected identities matched");
    });

    it("distinguishes verification that could not run from one that rejected", () => {
        // No verdict, but a reason: the trusted root was unreachable, so nothing
        // was actually checked. This must not read as a rejected signature.
        const { container } = renderCard(
            makeProvenance({ verificationError: "sigstore trusted root: TUF fetch failed" }),
            "signed",
        );

        expect(fieldValue(container, "Verification")).toBe("Could not verify");
        expect(fieldValue(container, "Reason")).toBe("sigstore trusted root: TUF fetch failed");
    });

    it("renders no Reason field on a successful verification", () => {
        const { container } = renderCard(
            makeProvenance({ verified: true, signerIssuer: "https://token.actions.githubusercontent.com", signerIdentity: "^https://github.com/pfenerty/ocidex/.*$" }),
            "verified",
        );

        expect(fieldValue(container, "Verification")).toMatch(/^Verified — keyless/);
        expect(fieldValue(container, "Reason")).toBeNull();
    });
});
