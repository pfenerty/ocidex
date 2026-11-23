// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { compareHref } from "./ArtifactHeader";

describe("compareHref", () => {
    // The header's Compare opens the change the tile states, both sides
    // filled in, instead of an empty diff that loses the artifact.
    it("opens the stated change with both SBOMs filled in", () => {
        expect(compareHref({ previous: "v1.5.0", delta: -6, fromSbomId: "a", toSbomId: "b" })).toBe("/diff?from=a&to=b");
    });

    it("falls back to an empty diff without a comparable change", () => {
        expect(compareHref(undefined)).toBe("/diff");
        expect(compareHref({ previous: "v1.5.0", delta: 0 })).toBe("/diff");
    });
});
