import { describe, it, expect } from "vitest";
import { criticalChange, entryText, evolutionLabel, evolutionLine, formatDelta, historyPoints, latestVerdict, sameVariantAsNewest, variantOf, versionDeltas } from "./versionDelta";
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

describe("criticalChange", () => {
    const rows = [
        { versionKey: "1.28.0-rc.1", arch: "amd64", critical: 5 },
        { versionKey: "1.27.4", arch: "amd64", critical: 23 },
        { versionKey: "1.27.1", arch: "amd64", critical: 105 },
    ];

    // The tile counts the headline version, not the newest row: a prerelease
    // above it in the table is not what it changed from or to.
    it("compares the named version with its own predecessor", () => {
        expect(criticalChange(rows, "1.27.4")).toEqual({ previous: "1.27.1", delta: -82, fromSbomId: undefined, toSbomId: undefined });
        const withIds = rows.map((r, i) => ({ ...r, sbomId: `s${i}` }));
        expect(criticalChange(withIds, "1.27.4")).toMatchObject({ fromSbomId: "s2", toSbomId: "s1" });
    });

    it("is undefined with nothing comparable or an unknown version", () => {
        expect(criticalChange(rows, "1.27.1")).toBeUndefined();
        expect(criticalChange(rows, "9.9.9")).toBeUndefined();
    });
});

describe("evolution", () => {
    it("keys a version by major and variant base", () => {
        expect(evolutionLine("3.15.2-slim-trixie")).toBe("3|trixie");
        expect(evolutionLine("3.14.0-alpine3.20")).toBe(evolutionLine("3.14.9-alpine3.21"));
        expect(evolutionLine("main-abc")).toBe("");
    });

    it("labels a major step and a base change", () => {
        expect(evolutionLabel("2.9.1", "3.0.0")).toBe("evolved · 2.x → 3.0.0");
        expect(evolutionLabel("v2.9.1", "v3.0.0")).toBe("evolved · 2.x → 3.0.0");
        expect(evolutionLabel("3.12.1-bookworm", "3.13.0-trixie")).toBe("evolved · bookworm → trixie");
    });

    it("says nothing within a line or across a version with no major", () => {
        expect(evolutionLabel("3.1.0", "3.2.0")).toBeUndefined();
        expect(evolutionLabel("main-abc", "3.0.0")).toBeUndefined();
    });
});
