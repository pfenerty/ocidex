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

    // "2 registrys" is what the -s rule produces unaided, and the words this
    // app counts most are exactly the irregular ones.
    it("takes an explicit plural for words that do not take a bare s", () => {
        expect(plural(2, "registry", "registries")).toBe("2 registries");
        expect(plural(0, "repository", "repositories")).toBe("0 repositories");
    });

    it("ignores the explicit plural in the singular", () => {
        expect(plural(1, "registry", "registries")).toBe("1 registry");
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

describe("timestamps that carry no information (ocidex-5692)", () => {
    it("treats the epoch, Go's zero time and garbage as absent", async () => {
        const { meaningfulDate } = await import("~/utils/format");
        expect(meaningfulDate("1970-01-01T00:00:00Z")).toBeUndefined();
        expect(meaningfulDate("0001-01-01T00:00:00Z")).toBeUndefined();
        expect(meaningfulDate("not a date")).toBeUndefined();
        expect(meaningfulDate(undefined)).toBeUndefined();
        expect(meaningfulDate("2026-09-06T08:09:00Z")).toBe("2026-09-06T08:09:00Z");
    });

    it("never renders a reproducible-build epoch as Dec 31, 1969", async () => {
        const { formatDate, formatDateTime, relativeDate } = await import("~/utils/format");
        for (const f of [formatDate, formatDateTime, relativeDate]) {
            expect(f("1970-01-01T00:00:00Z")).toBe("—");
        }
    });

    it("falls back to the ingest time when the build date is meaningless", async () => {
        const { buildTime } = await import("~/utils/format");
        expect(buildTime({ buildDate: "1970-01-01T00:00:00Z", createdAt: "2026-09-06T08:09:00Z" })).toBe(
            "2026-09-06T08:09:00Z",
        );
        expect(buildTime({ buildDate: "2026-08-01T00:00:00Z", createdAt: "2026-09-06T08:09:00Z" })).toBe(
            "2026-08-01T00:00:00Z",
        );
    });
});
