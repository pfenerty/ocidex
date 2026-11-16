import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Identifiers keep their case (ocidex-hre1, ocidex-iz0r.8).
 *
 * `.badge` used to carry `text-transform: uppercase`, and badges hold
 * identifiers as often as labels: advisory aliases rendered as
 * GHSA-X527-X647-Q7GG (not the id), cluster names as DEV-CLUSTER. Registry
 * group headers in tables did the same to "ghcr.io/acme". Uppercase is the
 * eyebrow style for fixed labels (column headers, stat labels) only.
 */
const css = readFileSync(join(__dirname, "index.css"), "utf-8").replace(/\/\*[\s\S]*?\*\//g, "");

function body(selector: string): string {
    const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const m = new RegExp(`(?:^|[\\s,}])${escaped}\\s*\\{([^}]*)\\}`, "m").exec(css);
    if (m === null) throw new Error(`no rule for ${selector}`);
    return m[1];
}

describe("identifier-bearing elements are never case-transformed", () => {
    it.each([".badge", "tr.group-header-row td"])("%s", (selector) => {
        expect(body(selector)).not.toMatch(/text-transform\s*:\s*(uppercase|lowercase|capitalize)/);
    });
});
