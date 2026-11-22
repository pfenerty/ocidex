import { describe, it, expect } from "vitest";
import { worstSeverity } from "./VulnTile";

const summary = (v: Partial<{ critical: number; high: number; medium: number; low: number; unknown: number }>) => {
    const s = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, ...v };
    return { ...s, total: s.critical + s.high + s.medium + s.low + s.unknown };
};

describe("worstSeverity", () => {
    // Unrated findings are the least severe: any rated one outranks them,
    // however many unrated there are.
    it("ranks a single low above any number of unknown", () => {
        expect(worstSeverity(summary({ low: 1, unknown: 240 }))).toEqual({ label: "low", count: 1 });
    });

    it("names unknown only when nothing is rated", () => {
        expect(worstSeverity(summary({ unknown: 3 }))).toEqual({ label: "unknown", count: 3 });
    });
});
