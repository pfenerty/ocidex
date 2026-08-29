// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { Router } from "@solidjs/router";
import { render } from "@solidjs/testing-library";
import { VersionsTab } from "./VersionsTab";
import type { ArtifactVersionSummary } from "~/api/client";
import type { SortDir } from "~/components/DataTable";

const version: ArtifactVersionSummary = {
    versionKey: "v1.2.3",
    sbomId: "11111111-1111-1111-1111-111111111111",
    sbomCount: 1,
    createdAt: "2026-01-01T00:00:00Z",
    architectures: null,
    signingStatus: "unsigned",
    sufficient: true,
};

function renderTab(
    isContainer: boolean,
    versions: ArtifactVersionSummary[] = [version],
    onSort: (key: string, dir: SortDir) => void = () => undefined,
) {
    return render(() => (
        <Router
            root={(props) => <>{props.children}</>}
        >
            {[
                {
                    path: "/",
                    component: () => (
                        <VersionsTab
                            artifactId="22222222-2222-2222-2222-222222222222"
                            isContainer={isContainer}
                            versions={versions}
                            pagination={undefined}
                            loading={false}
                            isError={false}
                            onPageChange={() => undefined}
                            sortBy={undefined}
                            sortDir="desc"
                            onSort={onSort}
                        />
                    ),
                },
            ]}
        </Router>
    ));
}

describe("VersionsTab column gating", () => {
    it("shows architecture and signing for a container", () => {
        const { getByText } = renderTab(true);
        expect(getByText("Architectures")).toBeDefined();
        expect(getByText("Signing")).toBeDefined();
    });

    // A binary or library has neither an architecture list nor a cosign
    // signature, so those columns would be a stripe of em-dashes (ocidex-rj4.3).
    it("omits architecture and signing for a non-container", () => {
        const { queryByText, getByText } = renderTab(false);
        expect(queryByText("Architectures")).toBeNull();
        expect(queryByText("Signing")).toBeNull();
        // Type-agnostic columns survive.
        expect(getByText("Version")).toBeDefined();
        expect(getByText("Build Date")).toBeDefined();
    });
});

describe("VersionsTab severity column", () => {
    // The whole point of the column is telling a scanned-and-clean version apart
    // from one nobody has looked at. VulnCountBadges renders an em dash for an
    // all-zero summary, which reads as "clean" — so the absent case has to be
    // caught before it gets there (ADR-044, ocidex-unn8.8).
    it("says not scanned when the version carries no summary", () => {
        const { getByText } = renderTab(true);
        expect(getByText("Vulnerabilities")).toBeDefined();
        expect(getByText("not scanned")).toBeDefined();
    });

    it("renders the per-severity counts when the version has findings", () => {
        const withVulns: ArtifactVersionSummary = {
            ...version,
            vulns: { critical: 2, high: 3, medium: 0, low: 1, unknown: 0, total: 6 },
        };
        const { container, queryByText } = renderTab(true, [withVulns]);
        expect(queryByText("not scanned")).toBeNull();
        const chip = container.querySelector(".vuln-chip");
        expect(chip?.textContent).toBe("23010");
    });

    // Sorting is server-side because the endpoint pages; a client-side sort
    // would silently reorder only the visible page.
    it("reports header clicks to the caller rather than sorting in place", () => {
        const calls: [string, SortDir][] = [];
        const { getByText } = renderTab(true, [version], (key, dir) =>
            calls.push([key, dir]),
        );
        getByText("Vulnerabilities").click();
        expect(calls).toEqual([["severity", "desc"]]);
    });
});
