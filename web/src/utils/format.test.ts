import { describe, it, expect } from "vitest";
import { shortDigest, shortId, plural, hasText, formatDate } from "./format";

describe("shortDigest", () => {
    it("truncates sha256 digest", () => {
        expect(shortDigest("sha256:abcdef1234567890abcdef1234567890")).toBe(
            "sha256:abcdef1234567890\u2026"
        );
    });

    it("truncates long non-sha256 string", () => {
        expect(shortDigest("a".repeat(30))).toBe(`${"a".repeat(24)}\u2026`);
    });

    it("returns short string as-is", () => {
        expect(shortDigest("short")).toBe("short");
    });
});

describe("shortId", () => {
    it("returns first 8 chars", () => {
        expect(shortId("a1b2c3d4-e5f6-7890-abcd-ef1234567890")).toBe("a1b2c3d4");
    });
});

describe("plural", () => {
    it("adds s for plural", () => {
        expect(plural(3, "component")).toBe("3 components");
    });

    it("no s for singular", () => {
        expect(plural(1, "SBOM")).toBe("1 SBOM");
    });

    it("adds s for zero", () => {
        expect(plural(0, "item")).toBe("0 items");
    });
});

describe("hasText", () => {
    it("returns true for non-empty string", () => {
        expect(hasText("hello")).toBe(true);
    });

    it("returns false for empty string", () => {
        expect(hasText("")).toBe(false);
    });

    it("returns false for null", () => {
        expect(hasText(null)).toBe(false);
    });

    it("returns false for undefined", () => {
        expect(hasText(undefined)).toBe(false);
    });
});

describe("formatDate", () => {
    it("formats ISO date", () => {
        const result = formatDate("2025-01-15T12:00:00Z");
        expect(result).toContain("Jan");
        expect(result).toContain("15");
        expect(result).toContain("2025");
    });
});
