import { describe, it, expect } from "vitest";
import { SCOPE_PRESETS, emptyForm, presetFor, prefillForHost, scopeWarning, LARGE_SCOPE_SBOMS } from "./registryTypes";

describe("scan scope presets (ADR-0053)", () => {
    it("starts a new registry on the bounded releases preset", () => {
        expect(presetFor(emptyForm())).toBe("releases");
        expect(emptyForm().tagLimit).toBe(50);
    });

    it("recognises each preset from its fields", () => {
        for (const [name, p] of Object.entries(SCOPE_PRESETS)) {
            expect(presetFor({ ...emptyForm(), ...p.fields })).toBe(name);
        }
    });

    it("ignores blank lines and whitespace in tag patterns", () => {
        expect(presetFor({ ...emptyForm(), tagPatterns: "\n semver \n" })).toBe("releases");
    });

    it("calls anything else custom", () => {
        expect(presetFor({ ...emptyForm(), tagLimit: 10 })).toBe("custom");
        expect(presetFor({ ...emptyForm(), tagPatterns: "v*" })).toBe("custom");
    });

    it("keeps a cluster-gap prefill on the default preset", () => {
        expect(presetFor({ ...emptyForm(), ...prefillForHost("ghcr.io", ["org/app"]) })).toBe("releases");
    });
});

describe("scopeWarning", () => {
    it("warns for an unlimited window whatever the estimate", () => {
        expect(scopeWarning(0, 3)).toMatch(/No tag limit/);
    });
    it("warns above the large-scope threshold only", () => {
        expect(scopeWarning(50, LARGE_SCOPE_SBOMS)).toBeUndefined();
        expect(scopeWarning(50, LARGE_SCOPE_SBOMS + 1)).toMatch(/2,001 SBOMs/);
        expect(scopeWarning(50, undefined)).toBeUndefined();
    });
});
