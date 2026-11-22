import { describe, it, expect } from "vitest";
import { isShiny } from "./Shiny";

describe("isShiny", () => {
    it("needs a match and zero findings", () => {
        expect(isShiny(true, 0)).toBe(true);
        expect(isShiny(true, undefined)).toBe(true);
        expect(isShiny(true, 3)).toBe(false);
        // Never matched: no findings is unknown, not clean.
        expect(isShiny(false, 0)).toBe(false);
        expect(isShiny(false, undefined)).toBe(false);
    });
});
