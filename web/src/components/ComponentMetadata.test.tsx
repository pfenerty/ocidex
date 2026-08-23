// @vitest-environment happy-dom
import { describe, it, expect, afterEach } from "vitest";
import { render, cleanup } from "@solidjs/testing-library";
import { Router } from "@solidjs/router";
import ComponentMetadata from "./ComponentMetadata";
import type { ComponentTab } from "./ComponentMetadata";

afterEach(cleanup);

const detailData = {
    id: "c1",
    sbomId: "s1",
    name: "zlib",
    type: "library",
    version: "1.3.1",
    purl: "pkg:generic/zlib@1.3.1",
    licenses: [{ id: "l1", name: "Zlib License", spdxId: "Zlib" }],
    hashes: [{ algorithm: "SHA-256", value: "abc123" }],
    externalReferences: [],
};

const vulnData = {
    data: [
        {
            id: "v1",
            canonicalId: "CVE-2026-1",
            severity: "HIGH",
            summary: "bad",
        },
    ],
};

// The two queries are only ever read, never re-created, so a plain object with
// the fields the component touches is a truer stand-in than a mocked hook.
const query = (data: unknown) =>
    ({ data, isFetching: false, isError: false, error: null }) as never;

function renderMetadata(props: { tab?: ComponentTab; onTabChange?: (t: ComponentTab) => void } = {}) {
    const rendered = render(() => (
        <Router root={(p) => <>{p.children}</>}>
            {[
                {
                    path: "/",
                    component: () => (
                        <ComponentMetadata
                            detailQuery={query(detailData)}
                            vulnsQuery={query(vulnData)}
                            showVulns={true}
                            tab={props.tab}
                            onTabChange={props.onTabChange}
                        />
                    ),
                },
            ]}
        </Router>
    ));
    const tabs = () => [...rendered.container.querySelectorAll(".tab-bar button")];
    return { ...rendered, tabs };
}

describe("ComponentMetadata tabs", () => {
    // The four tables were stacked, which is what put "what is this licensed
    // under" below a description of unbounded length.
    it("shows only the active section, starting on Details", () => {
        const { container, queryByText } = renderMetadata();
        expect(queryByText("Zlib License")).toBeNull();
        expect(queryByText("CVE-2026-1")).toBeNull();
        // Details carries the identity grid and the hashes table with it.
        expect(container.querySelector(".detail-grid")).not.toBeNull();
        expect(queryByText("abc123")).not.toBeNull();
    });

    it("counts each tab's contents in its label, so an empty tab reads as empty", () => {
        const { tabs } = renderMetadata();
        expect(tabs().map((t) => t.textContent)).toEqual([
            "Details",
            "Vulnerabilities (1)",
            "Licenses (1)",
        ]);
    });

    it("switches sections on its own when no caller drives it", () => {
        const { tabs, queryByText } = renderMetadata();
        (tabs()[2] as HTMLElement).click();
        expect(queryByText("Zlib License")).not.toBeNull();
        expect(queryByText("abc123")).toBeNull();
        expect(tabs()[2].className).toBe("active");
    });

    // The page owns the selection so a summary tile can open a tab; the strip
    // and the tile must not end up with two different ideas of which is active.
    it("follows the caller's tab when one is supplied, and reports clicks back", () => {
        const seen: ComponentTab[] = [];
        const { tabs, queryByText } = renderMetadata({
            tab: "vulns",
            onTabChange: (t) => seen.push(t),
        });
        expect(queryByText("CVE-2026-1")).not.toBeNull();
        expect(tabs()[1].className).toBe("active");
        (tabs()[0] as HTMLElement).click();
        expect(seen).toEqual(["details"]);
    });

    it("hides the vulnerabilities tab for a component with nothing to match on", () => {
        const { container } = render(() => (
            <Router root={(p) => <>{p.children}</>}>
                {[
                    {
                        path: "/",
                        component: () => (
                            <ComponentMetadata
                                detailQuery={query(detailData)}
                                vulnsQuery={query(vulnData)}
                                showVulns={false}
                                // Selected anyway: a tab that stops existing
                                // must fall back, not leave a blank panel.
                                tab="vulns"
                            />
                        ),
                    },
                ]}
            </Router>
        ));
        expect([...container.querySelectorAll(".tab-bar button")].map((t) => t.textContent)).toEqual(
            ["Details", "Licenses (1)"],
        );
        expect(container.querySelector(".detail-grid")).not.toBeNull();
    });
});
