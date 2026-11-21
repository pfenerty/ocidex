import { describe, it, expect } from "vitest";
import { formatDelta, latestVerdict, variantOf, versionDeltas } from "./versionDelta";

const py = [
    { versionKey: "3.15.2", critical: 33, high: 252 },
    { versionKey: "3.14.10", critical: 35, high: 269 },
    { versionKey: "3.14.9", critical: 75, high: 542 },
];

describe("versionDeltas", () => {
    it("compares each row with the one after it", () => {
        expect(versionDeltas(py)).toEqual([
            { critical: -2, high: -17 },
            { critical: -40, high: -273 },
            {},
        ]);
    });

    it("leaves a delta undefined across an unscanned version", () => {
        const rows = [{ versionKey: "b", critical: 3, high: 1 }, { versionKey: "a" }];
        expect(versionDeltas(rows)).toEqual([{ critical: undefined, high: undefined }, {}]);
    });
});

describe("variants", () => {
    it("reads the variant after the version number", () => {
        expect(variantOf("3.14.9-trixie")).toBe("trixie");
        expect(variantOf("3.14.4")).toBe("");
    });

    // Semver order put a Windows "3.14.4" between two Debian builds, and the
    // Debian build above it showed +443 critical against the Windows image.
    it("compares each version with the previous one of its own variant", () => {
        const rows = [
            { versionKey: "3.14.5-trixie", critical: 443, high: 2588 },
            { versionKey: "3.14.4", critical: 0, high: 1 },
            { versionKey: "3.14.4-trixie", critical: 451, high: 2596 },
        ];
        expect(versionDeltas(rows)).toEqual([{ critical: -8, high: -8 }, {}, {}]);
    });

    it("gives the verdict for the newest version's variant", () => {
        const rows = [
            { versionKey: "3.15.2-trixie", critical: 33, high: 1 },
            { versionKey: "3.15.1", critical: 0, high: 0 },
            { versionKey: "3.14.10-trixie", critical: 35, high: 1 },
        ];
        expect(latestVerdict(rows)).toMatchObject({ previous: "3.14.10-trixie", delta: -2 });
    });
});

describe("latestVerdict", () => {
    it("compares the newest two scanned versions", () => {
        expect(latestVerdict(py)).toEqual({ latest: "3.15.2", previous: "3.14.10", critical: 33, delta: -2 });
    });

    it("skips unscanned versions instead of reading them as zero", () => {
        const rows = [{ versionKey: "c" }, ...py];
        expect(latestVerdict(rows)?.latest).toBe("3.15.2");
    });

    it("has nothing to say with fewer than two scanned versions", () => {
        expect(latestVerdict([py[0]])).toBeUndefined();
        expect(latestVerdict([])).toBeUndefined();
    });
});

describe("formatDelta", () => {
    it("uses a real minus sign and a plus-minus for no change", () => {
        expect(formatDelta(-2)).toBe("−2");
        expect(formatDelta(1270)).toBe("+1,270");
        expect(formatDelta(0)).toBe("±0");
    });
});
