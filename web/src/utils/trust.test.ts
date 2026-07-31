import { describe, it, expect } from "vitest";
import {
    trustStatus,
    signingStatusLabel,
    trustBadgeClass,
    trustBadgeVariant,
    signingStatuses,
    driftReasonLabel,
    type TrustVariant,
} from "./trust";

describe("trustStatus", () => {
    const cases: { status: string; label: string; variant: TrustVariant }[] = [
        { status: "verified", label: "Verified", variant: "info" },
        { status: "signed", label: "Signed", variant: "neutral" },
        { status: "unsigned", label: "Unsigned", variant: "neutral" },
        { status: "artifact_missing", label: "Artifact missing", variant: "warning" },
        { status: "verification_failed", label: "Verification failed", variant: "danger" },
    ];

    for (const c of cases) {
        it(`describes ${c.status}`, () => {
            const t = trustStatus(c.status);
            expect(t).not.toBeNull();
            expect(t?.label).toBe(c.label);
            expect(t?.variant).toBe(c.variant);
            expect(t?.icon).toBeTypeOf("function");
            expect(t?.description.length).toBeGreaterThan(0);
        });
    }

    it("covers every status in signingStatuses", () => {
        for (const status of signingStatuses) {
            expect(trustStatus(status)).not.toBeNull();
        }
        expect(signingStatuses).toHaveLength(cases.length);
    });

    it("returns null for undefined and unknown statuses", () => {
        expect(trustStatus(undefined)).toBeNull();
        expect(trustStatus("not_a_status")).toBeNull();
    });

    // ADR-023 keeps amber as a sparing accent, and the trust axis is
    // deliberately green-free so "Verified" reads as brand-affirmed rather
    // than as a generic success state.
    it("uses no success variant anywhere on the trust axis", () => {
        for (const status of signingStatuses) {
            const t = trustStatus(status);
            expect(t).not.toBeNull();
            expect(trustBadgeVariant(t?.variant ?? "neutral")).not.toBe("success");
        }
    });

    // `signed` means "not checked", not "something is wrong" — it must not
    // borrow the warning styling reserved for artifact_missing.
    it("does not style signed as a warning", () => {
        expect(trustStatus("signed")?.variant).toBe("neutral");
        expect(trustBadgeClass("neutral")).toBe("badge");
    });
});

describe("signingStatusLabel", () => {
    it("labels known statuses", () => {
        expect(signingStatusLabel("artifact_missing")).toBe("Artifact missing");
    });

    it("falls back to the raw status", () => {
        expect(signingStatusLabel("not_a_status")).toBe("not_a_status");
    });
});

describe("trustBadgeVariant", () => {
    const cases: [TrustVariant, string][] = [
        ["info", "primary"],
        ["warning", "warning"],
        ["danger", "danger"],
        ["neutral", "default"],
    ];

    for (const [variant, want] of cases) {
        it(`maps ${variant} to ${want}`, () => {
            expect(trustBadgeVariant(variant)).toBe(want);
        });
    }
});

describe("trustBadgeClass", () => {
    it("renders verified with the brand-blue primary badge", () => {
        expect(trustBadgeClass("info")).toBe("badge badge-primary");
    });

    it("renders neutral as a bare badge", () => {
        expect(trustBadgeClass("neutral")).toBe("badge");
    });

    it("renders warning and danger badges", () => {
        expect(trustBadgeClass("warning")).toBe("badge badge-warning");
        expect(trustBadgeClass("danger")).toBe("badge badge-danger");
    });
});

describe("driftReasonLabel", () => {
    it("explains known reasons", () => {
        expect(driftReasonLabel("artifact_missing")).toBe("the artifact was removed from the registry");
    });

    it("falls back to the raw reason", () => {
        expect(driftReasonLabel("something_else")).toBe("something_else");
    });
});
