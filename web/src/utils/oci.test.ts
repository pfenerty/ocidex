import { describe, it, expect } from "vitest";

import { imageRefName } from "./oci";

describe("imageRefName", () => {
    const hex = "a".repeat(64);

    it("returns ordinary references unchanged", () => {
        expect(imageRefName("ghcr.io/pfenerty/ocidex/api:v1.2.3")).toBe(
            "ghcr.io/pfenerty/ocidex/api:v1.2.3",
        );
        expect(imageRefName("nginx")).toBe("nginx");
    });

    it("keeps a reference that carries a digest after a name", () => {
        expect(imageRefName(`nginx@sha256:${hex}`)).toBe(`nginx@sha256:${hex}`);
    });

    // These are the values that used to render as a wall of hex.
    it("reports a bare image id as unnamed", () => {
        expect(imageRefName(`sha256:${hex}`)).toBe(null);
        expect(imageRefName(hex)).toBe(null);
        expect(imageRefName(hex.toUpperCase())).toBe(null);
    });

    it("treats blank as unnamed", () => {
        expect(imageRefName("")).toBe(null);
        expect(imageRefName("   ")).toBe(null);
    });
});
