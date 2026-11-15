import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * A StatusPill is `badge badge-sm badge-<variant>`. All three rules have equal
 * specificity, so the one declared last wins: when `.badge-sm` came after the
 * variants it reset their colours and every pill — "erroring", "stale",
 * "never reported" — rendered the same grey (ocidex-70eo.4).
 */
describe("badge stylesheet", () => {
    const css = readFileSync(join(__dirname, "index.css"), "utf-8").replace(/\/\*[\s\S]*?\*\//g, "");

    it.each(["primary", "success", "danger", "warning"])("declares .badge-sm before .badge-%s", (variant) => {
        const sm = css.indexOf(".badge-sm {");
        const v = css.indexOf(`.badge-${variant} {`);
        expect(sm).toBeGreaterThan(-1);
        expect(v).toBeGreaterThan(sm);
    });
});
