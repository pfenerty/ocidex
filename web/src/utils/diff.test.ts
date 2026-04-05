import { describe, it, expect } from "vitest";
import { debVersionCompare, classifyChange } from "./diff";
import type { ComponentDiff } from "~/api/client";

describe("debVersionCompare", () => {
    it("equal versions return 0", () => {
        expect(debVersionCompare("1.0-1", "1.0-1")).toBe(0);
    });

    it("compares epoch first", () => {
        expect(debVersionCompare("2:1.0", "1:9.9")).toBe(1);
        expect(debVersionCompare("1:1.0", "2:1.0")).toBe(-1);
    });

    it("no epoch equals epoch 0", () => {
        expect(debVersionCompare("1.0", "0:1.0")).toBe(0);
    });

    it("compares upstream version numerically", () => {
        expect(debVersionCompare("1.10", "1.9")).toBe(1);
        expect(debVersionCompare("1.2", "1.10")).toBe(-1);
    });

    it("compares revision when upstream matches", () => {
        expect(debVersionCompare("1.0-2", "1.0-1")).toBe(1);
        expect(debVersionCompare("1.0-1", "1.0-2")).toBe(-1);
    });

    it("handles tilde as lower than everything", () => {
        expect(debVersionCompare("1.0~beta1", "1.0")).toBe(-1);
        expect(debVersionCompare("1.0~alpha", "1.0~beta")).toBe(-1);
    });

    it("handles alphabetic suffixes", () => {
        expect(debVersionCompare("1.0a", "1.0b")).toBe(-1);
    });

    it("handles versions without revision", () => {
        expect(debVersionCompare("1.0", "1.0-1")).toBe(-1);
    });
});

function makeDiff(overrides: Partial<ComponentDiff> & { type: string; name: string }): ComponentDiff {
    return { purl: "", ...overrides } as ComponentDiff;
}

describe("classifyChange", () => {
    it("returns added for added type", () => {
        expect(classifyChange(makeDiff({ type: "added", name: "foo" }))).toBe("added");
    });

    it("returns removed for removed type", () => {
        expect(classifyChange(makeDiff({ type: "removed", name: "foo" }))).toBe("removed");
    });

    it("returns upgraded when version increases", () => {
        expect(classifyChange(makeDiff({
            type: "modified",
            name: "foo",
            version: "2.0",
            previousVersion: "1.0",
        }))).toBe("upgraded");
    });

    it("returns downgraded when version decreases", () => {
        expect(classifyChange(makeDiff({
            type: "modified",
            name: "foo",
            version: "1.0",
            previousVersion: "2.0",
        }))).toBe("downgraded");
    });

    it("returns modified when versions are equal", () => {
        expect(classifyChange(makeDiff({
            type: "modified",
            name: "foo",
            version: "1.0",
            previousVersion: "1.0",
        }))).toBe("modified");
    });

    it("returns modified when versions are missing", () => {
        expect(classifyChange(makeDiff({
            type: "modified",
            name: "foo",
        }))).toBe("modified");
    });
});
