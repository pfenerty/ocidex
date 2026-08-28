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
