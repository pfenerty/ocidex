import { describe, it, expect } from "vitest";
import { entryText, formatDelta, historyPoints, latestVerdict, sameVariantAsNewest, variantOf, versionDeltas } from "./versionDelta";
import golden from "./versionLine.golden.json";

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

    it.each(golden)("agrees with the server on $version", ({ version, variant }) => {
        expect(variantOf(version)).toBe(variant);
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

describe("entryText", () => {
    const line = [
        { versionKey: "3.15.2", critical: 33 },
        { versionKey: "3.14.10", critical: 35 },
        { versionKey: "3.14.6", critical: 286 },
        { versionKey: "3.14.4", critical: 451 },
    ];

    it("summarises a falling history", () => {
        expect(entryText(line, 9)).toBe(
            "Nine versions on record. Critical findings have not gone up in any release since 3.14.4: 451 in 3.14.4, 33 in 3.15.2. 3.14.10 shed the most at once, 251.",
        );
    });

    it("says when findings rose", () => {
        const rising = [{ versionKey: "2", critical: 5 }, { versionKey: "1", critical: 3 }];
        expect(entryText(rising, 2)).toBe("Two versions on record. Critical findings rose in at least one release: 3 in 1, 5 in 2.");
    });

    it("says nothing with one comparable version", () => {
        expect(entryText([line[0]], 1)).toBeUndefined();
    });
});

// Live golang: 1.27.4-trixie was counted on its only SBOM, riscv64, and
// 1.27.1-trixie on amd64, and the page reported −82 critical between two
// different architectures' package sets.
describe("same-architecture comparison", () => {
    const rows = [
        { versionKey: "1.27.4-trixie", arch: "riscv64", critical: 10, high: 40 },
        { versionKey: "1.27.1-trixie", arch: "amd64", critical: 92, high: 300 },
        { versionKey: "1.27.0-trixie", arch: "amd64", critical: 95, high: 310 },
    ];

    it("gives no delta against a version counted on another architecture", () => {
        expect(versionDeltas(rows)).toEqual([{ noSharedArch: true }, { critical: -3, high: -10 }, {}]);
    });

    it("skips to the next version on the same architecture", () => {
        const withRiscv = [...rows, { versionKey: "1.26.0-trixie", arch: "riscv64", critical: 12, high: 41 }];
        expect(versionDeltas(withRiscv)[0]).toEqual({ critical: -2, high: -1 });
    });

    it("keeps the verdict, chart line and entry text on one architecture", () => {
        expect(latestVerdict(rows)).toBeUndefined();
        expect(sameVariantAsNewest(rows).map((r) => r.versionKey)).toEqual(["1.27.4-trixie"]);
        expect(entryText(rows, 3)).toBeUndefined();
    });

    it("compares versions whose architecture is unknown on both sides", () => {
        expect(versionDeltas([{ versionKey: "2.0.0", critical: 1 }, { versionKey: "1.0.0", critical: 3 }])[0]).toEqual({
            critical: -2,
            high: undefined,
        });
    });
});

describe("historyPoints", () => {
    it("reads an empty architecture as unknown", () => {
        expect(historyPoints([{ versionKey: "1.0.0", critical: 2, architecture: "" }, { versionKey: "0.9.0", architecture: "amd64" }])).toEqual([
            { versionKey: "1.0.0", arch: undefined, critical: 2 },
            { versionKey: "0.9.0", arch: "amd64", critical: undefined },
        ]);
        expect(historyPoints(null)).toEqual([]);
    });
});
