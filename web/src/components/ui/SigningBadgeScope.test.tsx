// @vitest-environment happy-dom
import { describe, it, expect, afterEach } from "vitest";
import { render, cleanup } from "@solidjs/testing-library";
import { SigningBadge } from "./SigningBadge";

afterEach(cleanup);

// On the artifact header the chip sits beside latest-version figures but
// reports the worst status across every SBOM, so it names its scope.
describe("SigningBadge scope", () => {
    const scope = { label: "any SBOM", description: "Worst status across every SBOM of this artifact." };

    it("shows the scope label after the status", () => {
        const { container } = render(() => <SigningBadge status="verification_failed" scope={scope} />);
        expect(container.textContent).toBe("Verification failedany SBOM");
    });

    it("shows no scope label without one", () => {
        const { container } = render(() => <SigningBadge status="signed" />);
        expect(container.textContent).not.toContain("any SBOM");
    });
});
