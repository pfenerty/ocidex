// @vitest-environment happy-dom
import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, it, expect, afterEach } from "vitest";
import { Router, Route } from "@solidjs/router";
import { render, cleanup } from "@solidjs/testing-library";
import About from "~/pages/About";
import { DATA_SOURCES } from "~/pages/About/dataSources";

afterEach(cleanup);

/** The source rows of docs/DATA_SOURCES.md's table: first cell, link text only. */
function documentedSources(): string[] {
    const md = readFileSync(path.resolve(import.meta.dirname, "../../../../docs/DATA_SOURCES.md"), "utf8");
    return md
        .split("\n")
        .filter((line) => line.startsWith("| ") && !line.startsWith("| Source") && !line.startsWith("|---"))
        .map((line) => line.split("|")[1].trim().replace(/^\[(.*)\]\(.*\)$/, "$1"));
}

describe("About", () => {
    // The page repeats docs/DATA_SOURCES.md so the attribution is where the
    // data is shown; this keeps the two from drifting apart.
    it("lists exactly the data sources DATA_SOURCES.md documents", () => {
        expect(DATA_SOURCES.map((s) => s.name)).toEqual(documentedSources());
    });

    it("links the bundle's third-party licenses and credits each feed", () => {
        const { container } = render(() => (
            <Router>
                <Route path="*" component={About} />
            </Router>
        ));
        const link = container.querySelector('a[href="/third-party-licenses.txt"]');
        expect(link).not.toBeNull();
        expect(container.textContent).toContain("/licenses");
        for (const src of DATA_SOURCES) {
            expect(container.textContent).toContain(src.name);
        }
        expect(container.textContent).toContain("not endorsed or certified by the NVD");
    });
});
