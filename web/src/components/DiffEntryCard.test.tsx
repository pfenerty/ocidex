// @vitest-environment happy-dom
import { describe, it, expect, vi } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
import { DiffEntryCard } from "./DiffEntryCard";
import type { ChangelogEntryData } from "~/utils/diff";

vi.mock("@solidjs/router", () => ({
    A: (props: { href: string; children?: unknown; class?: string }) => (
        <a href={props.href} class={props.class}>{props.children as never}</a>
    ),
}));

// Stub DiffPairView so we can detect whether the body was mounted.
vi.mock("~/components/DiffPairView", () => ({
    DiffPairView: () => <div data-testid="diff-pair-body">body</div>,
}));

function makeEntry(overrides: Partial<ChangelogEntryData> = {}): ChangelogEntryData {
    return {
        from: {
            id: "from-id",
            createdAt: "2026-04-01T00:00:00Z",
            subjectVersion: "v2.30.3",
        },
        to: {
            id: "to-id",
            createdAt: "2026-04-15T00:00:00Z",
            subjectVersion: "v2.31.0",
        },
        summary: { added: 30, removed: 18, upgraded: 82, downgraded: 1, modified: 0 },
        changes: [],
        ...overrides,
    };
}

describe("DiffEntryCard", () => {
    it("renders header with from→to and summary badges, even when collapsed", () => {
        const { getByText, queryByTestId } = render(() => (
            <DiffEntryCard entry={makeEntry()} viewMode="tree" defaultExpanded={false} />
        ));
        // Header shows both versions.
        expect(getByText(/v2\.30\.3/)).toBeDefined();
        expect(getByText(/v2\.31\.0/)).toBeDefined();
        // Summary badges visible.
        expect(getByText(/\+30 added/)).toBeDefined();
        expect(getByText(/-18 removed/)).toBeDefined();
        expect(getByText(/↑82 upgraded/)).toBeDefined();
        expect(getByText(/↓1 downgraded/)).toBeDefined();
        // Body NOT mounted in collapsed state.
        expect(queryByTestId("diff-pair-body")).toBeNull();
    });

    it("mounts the body when defaultExpanded=true", () => {
        const { queryByTestId } = render(() => (
            <DiffEntryCard entry={makeEntry()} viewMode="tree" defaultExpanded={true} />
        ));
        expect(queryByTestId("diff-pair-body")).not.toBeNull();
    });

    it("toggles expansion on header click", () => {
        const { getByRole, queryByTestId } = render(() => (
            <DiffEntryCard entry={makeEntry()} viewMode="tree" defaultExpanded={false} />
        ));
        // Initially collapsed.
        expect(queryByTestId("diff-pair-body")).toBeNull();
        // Click header.
        const header = getByRole("button");
        fireEvent.click(header);
        expect(queryByTestId("diff-pair-body")).not.toBeNull();
        // Click again to collapse.
        fireEvent.click(header);
        expect(queryByTestId("diff-pair-body")).toBeNull();
    });

    it("hides zero-count summary badges", () => {
        const entry = makeEntry({
            summary: { added: 0, removed: 0, upgraded: 5, downgraded: 0, modified: 0 },
        });
        const { queryByText, getByText } = render(() => (
            <DiffEntryCard entry={entry} viewMode="tree" defaultExpanded={false} />
        ));
        expect(getByText(/↑5 upgraded/)).toBeDefined();
        expect(queryByText(/added/)).toBeNull();
        expect(queryByText(/removed/)).toBeNull();
        expect(queryByText(/downgraded/)).toBeNull();
    });
});
