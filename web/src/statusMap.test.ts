import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { AGENT_HEALTH_STATUS, MATCH_STATUS, VULN_DATA_STATUS, type Tone } from "~/utils/status";

/**
 * One status vocabulary (ocidex-iz0r.4). The cluster page used to colour "no
 * SBOM" amber in its legend and red in every row, and "never scanned" had five
 * spellings, some of which also meant "clean".
 */
const SRC = __dirname;
const css = readFileSync(join(SRC, "index.css"), "utf-8");

function sources(dir = SRC, acc: string[] = []): string[] {
    for (const e of readdirSync(dir)) {
        const full = join(dir, e);
        if (statSync(full).isDirectory()) sources(full, acc);
        else if (/\.tsx?$/.test(e) && !/\.test\.tsx?$/.test(e)) acc.push(full);
    }
    return acc;
}

describe("status map", () => {
    const tones = new Set<Tone>(
        [MATCH_STATUS, VULN_DATA_STATUS, AGENT_HEALTH_STATUS].flatMap((m) => Object.values(m).map((s) => s.tone)),
    );

    it.each([...tones])("tone %s has a chip style and a fill", (tone) => {
        expect(css).toContain(`.status-${tone}`);
        expect(css).toContain(`.tone-fill-${tone}`);
    });

    it("keeps never-scanned visibly apart from clean", () => {
        expect(VULN_DATA_STATUS.unscanned.tone).toBe("unknown");
        expect(VULN_DATA_STATUS.clean.tone).toBe("ok");
    });

    it("feeds the coverage legend from the same entries as the row chips", () => {
        const band = readFileSync(join(SRC, "pages/ClusterDetail/CoverageBand.tsx"), "utf-8");
        for (const state of ["exact", "unknown", "unresolvable"]) {
            expect(band).toContain(`MATCH_STATUS.${state}.tone`);
        }
        const clusterCss = readFileSync(join(SRC, "pages/ClusterDetail/ClusterDetail.css"), "utf-8");
        expect(clusterCss).not.toMatch(/\.coverage-(bar|segment)-(matched|unknown|unresolvable)/);
    });

    it("leaves none of the retired spellings in the UI", () => {
        const retired = /[>"]\s*(not assessed|none known|no findings)\s*[<"]/;
        const offenders = sources()
            .filter((f) => !f.endsWith("utils/status.ts"))
            .filter((f) =>
                retired.test(readFileSync(f, "utf-8").replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, "")),
            )
            .map((f) => f.slice(SRC.length + 1));
        expect(offenders).toEqual([]);
    });
});
