import { describe, it, expect } from "vitest";
import { parsePurl, purlToRegistryUrl, purlDisplayName, purlTypeLabel } from "./purl";

describe("parsePurl", () => {
    it("parses simple purl", () => {
        expect(parsePurl("pkg:npm/lodash@4.17.21")).toEqual({
            type: "npm",
            namespace: undefined,
            name: "lodash",
            version: "4.17.21",
        });
    });

    it("parses purl with namespace", () => {
        expect(parsePurl("pkg:maven/org.apache/commons-lang3@3.12")).toEqual({
            type: "maven",
            namespace: "org.apache",
            name: "commons-lang3",
            version: "3.12",
        });
    });

    it("parses purl without version", () => {
        expect(parsePurl("pkg:npm/lodash")).toEqual({
            type: "npm",
            namespace: undefined,
            name: "lodash",
            version: undefined,
        });
    });

    it("parses scoped npm purl", () => {
        expect(parsePurl("pkg:npm/%40types/node@18.0.0")).toEqual({
            type: "npm",
            namespace: "%40types",
            name: "node",
            version: "18.0.0",
        });
    });

    it("strips qualifiers and subpath", () => {
        expect(parsePurl("pkg:golang/github.com/foo/bar@v1.0.0?type=module#sub")).toEqual({
            type: "golang",
            namespace: "github.com/foo",
            name: "bar",
            version: "v1.0.0",
        });
    });

    it("returns null for invalid purl", () => {
        expect(parsePurl("not-a-purl")).toBeNull();
        expect(parsePurl("")).toBeNull();
    });
});

describe("purlToRegistryUrl", () => {
    it("generates npm URL", () => {
        expect(purlToRegistryUrl("pkg:npm/lodash@4.17.21")).toBe(
            "https://www.npmjs.com/package/lodash/v/4.17.21"
        );
    });

    it("generates PyPI URL", () => {
        expect(purlToRegistryUrl("pkg:pypi/requests@2.28.0")).toBe(
            "https://pypi.org/project/requests/2.28.0/"
        );
    });

    it("generates Go URL", () => {
        expect(purlToRegistryUrl("pkg:golang/github.com/foo/bar@v1.0.0")).toBe(
            "https://pkg.go.dev/github.com/foo/bar@v1.0.0"
        );
    });

    it("returns null for unsupported type", () => {
        expect(purlToRegistryUrl("pkg:unknown/something")).toBeNull();
    });

    it("returns null for invalid purl", () => {
        expect(purlToRegistryUrl("garbage")).toBeNull();
    });
});

describe("purlDisplayName", () => {
    it("returns namespace/name@version", () => {
        expect(purlDisplayName("pkg:maven/org.example/lib@1.0")).toBe("org.example/lib@1.0");
    });

    it("returns name@version without namespace", () => {
        expect(purlDisplayName("pkg:npm/lodash@4.0")).toBe("lodash@4.0");
    });

    it("returns name without version", () => {
        expect(purlDisplayName("pkg:npm/lodash")).toBe("lodash");
    });

    it("returns raw string for invalid purl", () => {
        expect(purlDisplayName("garbage")).toBe("garbage");
    });
});

describe("purlTypeLabel", () => {
    it("returns human label for known types", () => {
        expect(purlTypeLabel("pkg:npm/x")).toBe("npm");
        expect(purlTypeLabel("pkg:pypi/x")).toBe("PyPI");
        expect(purlTypeLabel("pkg:golang/x")).toBe("Go");
        expect(purlTypeLabel("pkg:deb/x")).toBe("Debian");
    });

    it("returns raw type for unknown types", () => {
        expect(purlTypeLabel("pkg:custom/x")).toBe("custom");
    });

    it("returns null for invalid purl", () => {
        expect(purlTypeLabel("garbage")).toBeNull();
    });
});
