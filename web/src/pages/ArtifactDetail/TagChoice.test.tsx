// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import type { ArtifactVersionSummary } from "~/api/client";
import { fewestCriticals, fixLine } from "./TagChoice";

const v = (versionKey: string, flavor: string, critical: number, high: number, matched = true): ArtifactVersionSummary =>
    ({
        versionKey,
        flavor,
        vulnMatched: matched,
        vulns: { critical, high, medium: 0, low: 0, unknown: 0, fixable: critical + high },
    }) as ArtifactVersionSummary;

describe("fewestCriticals", () => {
    it("picks across lines, from each line's newest scanned version only", () => {
        const list = [
            v("v2.46.1", "alpine", 2, 36),
            v("v2.46.1-distroless", "debian", 1, 21),
            v("v2.45.0", "alpine", 0, 0), // older than the line's newest: no
        ];
        expect(fewestCriticals(list)?.versionKey).toBe("v2.46.1-distroless");
    });

    it("skips unscanned versions, which only look clean", () => {
        expect(fewestCriticals([v("2", "a", 0, 0, false), v("1", "a", 3, 0)])?.versionKey).toBe("1");
    });

    it("breaks a critical tie on highs", () => {
        expect(fewestCriticals([v("1", "a", 1, 9), v("1-x", "b", 1, 2)])?.versionKey).toBe("1-x");
    });
});

describe("fixLine", () => {
    it("says how many findings have no fix", () => {
        expect(fixLine({ critical: 2, high: 30, medium: 5, low: 0, unknown: 0, fixable: 16 }, true)).toBe(
            "2 critical · 21 findings with no fix",
        );
    });

    it("says when every finding has a fix", () => {
        expect(fixLine({ critical: 1, high: 33, medium: 0, low: 0, unknown: 0, fixable: 34 }, true)).toBe(
            "1 critical · all 34 findings have an upstream fix",
        );
    });

    it("tells clean from unscanned", () => {
        expect(fixLine(undefined, true)).toBe("no known vulnerabilities");
        expect(fixLine(undefined, false)).toBe("not scanned yet");
    });
});