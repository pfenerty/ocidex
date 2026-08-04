// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
import { SigningBadge } from "./SigningBadge";
import { signingStatuses, trustStatus } from "~/utils/trust";

function badge(status: string): HTMLElement {
    const { container } = render(() => <SigningBadge status={status} />);
    const el = container.querySelector("span.badge");
    if (el === null) throw new Error(`no badge rendered for status ${status}`);
    return el as HTMLElement;
}

describe("SigningBadge", () => {
    const cases: [string, string][] = [
        ["verified", "Verified"],
        ["signed", "Signed"],
        ["unsigned", "Unsigned"],
        ["artifact_missing", "Artifact missing"],
        ["verification_failed", "Verification failed"],
    ];

    for (const [status, label] of cases) {
        it(`labels ${status} as "${label}"`, () => {
            expect(badge(status).textContent).toContain(label);
        });
    }

    // Regression: SigningBadge used to carry its own hardcoded status table
    // with no artifact_missing case, so an artifact deleted from the registry
    // fell through to the fallback and rendered as a plain grey "Unsigned" —
    // the opposite of what trust.ts reported everywhere else.
    it("renders artifact_missing as its own status, never as Unsigned", () => {
        const el = badge("artifact_missing");
        expect(el.textContent).toContain("Artifact missing");
        expect(el.textContent).not.toContain("Unsigned");
        expect(el.className).toContain("badge-warning");
    });

    it("renders verified in brand blue, not green", () => {
        const el = badge("verified");
        expect(el.className).toContain("badge-primary");
        expect(el.className).not.toContain("badge-success");
    });

    // `signed` means "no cryptographic check was performed" — an OCIDex
    // configuration gap, not a defect in the artifact. It must not be styled
    // as a warning.
    it("renders signed as neutral with no warning styling", () => {
        const el = badge("signed");
        expect(el.className).not.toContain("badge-warning");
        expect(el.className).not.toContain("badge-danger");
        expect(el.className.trim()).toBe("badge");
    });

    it("renders verification_failed as danger", () => {
        expect(badge("verification_failed").className).toContain("badge-danger");
    });

    // The badge is now the only place a status is explained — the Artifacts
    // page dropped its standing legend block. The description therefore has to
    // be reachable by keyboard, not just on hover, and has to be associated
    // with the badge rather than merely rendered somewhere on the page.
    it("exposes every status description on focus, wired by aria-describedby", () => {
        for (const status of signingStatuses) {
            const { container, unmount } = render(() => <SigningBadge status={status} />);
            const trigger = container.querySelector("span.tooltip-trigger");
            if (trigger === null) throw new Error(`no tooltip trigger for ${status}`);

            fireEvent.focus(trigger);

            const id = trigger.getAttribute("aria-describedby");
            if (id === null) throw new Error(`no tooltip shown for ${status}`);
            expect(document.getElementById(id)?.textContent).toBe(
                trustStatus(status)?.description,
            );

            unmount();
        }
    });

    // A native title would render a second, unstyled tooltip alongside the
    // real one on hover.
    it("does not also carry a native title attribute", () => {
        for (const status of signingStatuses) {
            expect(badge(status).getAttribute("title")).toBe(null);
        }
    });

    it("renders an unknown status verbatim rather than relabelling it", () => {
        const el = badge("some_future_status");
        expect(el.textContent).toContain("some_future_status");
        expect(el.textContent).not.toContain("Unsigned");
    });
});
