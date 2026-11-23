// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { Router } from "@solidjs/router";
import { render } from "@solidjs/testing-library";
import { ChangelogTab } from "./ChangelogTab";
import type { ChangelogEntryData } from "~/utils/diff";
import type { PaginationMeta } from "~/api/client";

function entry(from: string, to: string, added: number): ChangelogEntryData {
    return {
        from: {
            id: "11111111-1111-1111-1111-111111111111",
            subjectVersion: from,
            createdAt: "2026-01-01T00:00:00Z",
        },
        to: {
            id: "22222222-2222-2222-2222-222222222222",
            subjectVersion: to,
            createdAt: "2026-01-02T00:00:00Z",
        },
        summary: { added, removed: 0, upgraded: 0, downgraded: 0, modified: 0 },
        changes: [],
    };
}

function renderTab(
    entries: ChangelogEntryData[],
    pagination: PaginationMeta | undefined,
    onPageChange: (offset: number) => void = () => undefined,
    architectures: string[] = ["amd64"],
) {
    return render(() => (
        <Router root={(props) => <>{props.children}</>}>
            {[
                {
                    path: "/",
                    component: () => (
                        <ChangelogTab
                            entries={entries}
                            pagination={pagination}
                            onPageChange={onPageChange}
                            availableArchitectures={architectures}
                            selectedArch="amd64"
                            order={<span class="test-order">order</span>}
                            onArchChange={() => undefined}
                            availableFlavors={[]}
                            selectedFlavor={undefined}
                            onFlavorChange={() => undefined}
                            viewMode="tree"
                            onViewModeChange={() => undefined}
                        />
                    ),
                },
            ]}
        </Router>
    ));
}

describe("ChangelogTab pagination", () => {
    // The timeline is a page of a longer history (ocidex-7gf7.4). Without this
    // control the tab silently shows the newest 20 entries of a thousand and
    // gives no way to reach the rest.
    it("renders the page controls and the range the page covers", () => {
        const { getByText } = renderTab([entry("v1.1.0", "v1.2.0", 3)], {
            total: 40,
            limit: 20,
            offset: 0,
        });
        expect(getByText("Showing 1–20 of 40")).toBeDefined();
        expect(getByText("1 / 2")).toBeDefined();
    });

    it("reports the offset of the page asked for", () => {
        let requested: number | undefined;
        const { getByLabelText } = renderTab(
            [entry("v1.1.0", "v1.2.0", 3)],
            { total: 40, limit: 20, offset: 0 },
            (offset) => {
                requested = offset;
            },
        );
        getByLabelText("Next page").click();
        expect(requested).toBe(20);
    });
});

describe("ChangelogTab zero-change entries", () => {
    // The server no longer drops a pair whose versions carry identical package
    // sets — the entry count has to be knowable without diffing every pair for
    // the timeline to be pageable. A card with no badges at all reads as a
    // rendering fault, so it says so instead.
    it("labels a pair with no package changes", () => {
        const { getByText } = renderTab([entry("v1.7.0", "v1.8.0", 0)], undefined);
        expect(getByText("no package changes")).toBeDefined();
    });

    it("does not label a pair that has changes", () => {
        const { queryByText } = renderTab([entry("v1.1.0", "v1.2.0", 3)], undefined);
        expect(queryByText("no package changes")).toBeNull();
        expect(queryByText("+3 added")).not.toBeNull();
    });
});

describe("ChangelogTab controls", () => {
    // Order, architecture and view used to take three rows for one entry.
    it("puts order, architecture and view on one row", () => {
        const { container } = renderTab([entry("1.0", "1.1", 1)], undefined, undefined, ["amd64", "arm64"]);
        const row = container.querySelector(".changelog-controls");
        expect(row?.querySelector(".test-order")).not.toBeNull();
        expect(row?.textContent).toContain("arm64");
        expect(row?.querySelector(".changelog-controls-end")).not.toBeNull();
    });

    it("switches the architecture pills to a picker past four", () => {
        const archs = ["amd64", "arm64", "arm", "ppc64le", "s390x"];
        const many = renderTab([entry("1.0", "1.1", 1)], undefined, undefined, archs).container;
        expect(many.querySelector(".changelog-arch-picker")).not.toBeNull();
        const few = renderTab([entry("1.0", "1.1", 1)], undefined, undefined, archs.slice(0, 4)).container;
        expect(few.querySelector(".changelog-arch-picker")).toBeNull();
    });
});
