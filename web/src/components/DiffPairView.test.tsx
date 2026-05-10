// @vitest-environment happy-dom
import { describe, it, expect, vi } from "vitest";
import { render } from "@solidjs/testing-library";
import { DiffPairView } from "./DiffPairView";
import type { DiffTree } from "~/api/client";

vi.mock("@solidjs/router", () => ({
    A: (props: { href: string; children?: unknown; class?: string }) => (
        <a href={props.href} class={props.class}>{props.children as never}</a>
    ),
}));

interface MockQueryResult {
    isLoading: boolean;
    isError: boolean;
    data?: DiffTree;
    error?: unknown;
}
const mockUseDiffTree = vi.fn<() => MockQueryResult>();
vi.mock("~/api/queries", () => ({
    useDiffTree: () => mockUseDiffTree(),
}));

function makeTree(fromArch: string | undefined, toArch: string | undefined): DiffTree {
    return {
        from: { id: "from-id", createdAt: "2026-05-01T00:00:00Z", architecture: fromArch },
        to: { id: "to-id", createdAt: "2026-05-02T00:00:00Z", architecture: toArch },
        summary: { added: 0, removed: 0, upgraded: 0, downgraded: 0, modified: 0 },
        changes: [],
        nodes: [],
        edges: [],
        roots: [],
    };
}

describe("DiffPairView cross-arch banner", () => {
    it("shows a warning banner when from and to architectures differ", () => {
        mockUseDiffTree.mockReturnValue({
            isLoading: false,
            isError: false,
            data: makeTree("aarch64", "s390x"),
        });
        const { getByText } = render(() => (
            <DiffPairView fromId="a" toId="b" viewMode="tree" />
        ));
        expect(getByText(/across architectures|cross.?arch/i)).toBeDefined();
    });

    it("does not show the banner when architectures match", () => {
        mockUseDiffTree.mockReturnValue({
            isLoading: false,
            isError: false,
            data: makeTree("aarch64", "aarch64"),
        });
        const { queryByText } = render(() => (
            <DiffPairView fromId="a" toId="b" viewMode="tree" />
        ));
        expect(queryByText(/across architectures|cross.?arch/i)).toBeNull();
    });

    it("does not show the banner when one side has no arch info", () => {
        mockUseDiffTree.mockReturnValue({
            isLoading: false,
            isError: false,
            data: makeTree(undefined, "aarch64"),
        });
        const { queryByText } = render(() => (
            <DiffPairView fromId="a" toId="b" viewMode="tree" />
        ));
        expect(queryByText(/across architectures|cross.?arch/i)).toBeNull();
    });
});
