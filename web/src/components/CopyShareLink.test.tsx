// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { artifactLookupPath, sbomLookupPath } from "~/components/CopyShareLink";

describe("artifactLookupPath", () => {
    it("carries every ladder rung the record has", () => {
        const path = artifactLookupPath({
            name: "ghcr.io/pfenerty/ocidex",
            type: "container",
            group: "pfenerty",
        });

        const url = new URL(path, "https://ocidex.test");
        expect(url.pathname).toBe("/artifacts/lookup");
        expect(url.searchParams.get("name")).toBe("ghcr.io/pfenerty/ocidex");
        expect(url.searchParams.get("type")).toBe("container");
        expect(url.searchParams.get("group")).toBe("pfenerty");
    });

    it("omits qualifiers the record does not have", () => {
        const url = new URL(
            artifactLookupPath({ name: "myapp", type: "container", group: "" }),
            "https://ocidex.test",
        );

        expect(url.searchParams.has("group")).toBe(false);
    });

    it("escapes a name with slashes so it survives a paste", () => {
        const path = artifactLookupPath({ name: "ghcr.io/pfenerty/ocidex" });

        // The slashes must not read as extra path segments.
        expect(path).toBe("/artifacts/lookup?name=ghcr.io%2Fpfenerty%2Focidex");
        expect(
            new URL(path, "https://ocidex.test").searchParams.get("name"),
        ).toBe("ghcr.io/pfenerty/ocidex");
    });
});

describe("sbomLookupPath", () => {
    it("keys on the digest", () => {
        const url = new URL(
            sbomLookupPath({ digest: "sha256:abc" }) ?? "",
            "https://ocidex.test",
        );

        expect(url.pathname).toBe("/sboms/lookup");
        expect(url.searchParams.get("digest")).toBe("sha256:abc");
    });

    it("returns null when there is no digest to key on", () => {
        expect(sbomLookupPath({})).toBe(null);
        expect(sbomLookupPath({ digest: "" })).toBe(null);
    });
});
