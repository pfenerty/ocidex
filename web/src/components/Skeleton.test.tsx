// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { render } from "@solidjs/testing-library";
import { Skeleton, SkeletonText, SkeletonTable, SkeletonCard, SkeletonHeader } from "./Skeleton";

describe("Skeleton", () => {
    it("renders a single shimmer block honoring width", () => {
        const { container } = render(() => <Skeleton width="8rem" />);
        const els = container.querySelectorAll(".skeleton");
        expect(els).toHaveLength(1);
        expect((els[0] as HTMLElement).style.width).toBe("8rem");
    });

    it("adds the circle modifier when circle is set", () => {
        const { container } = render(() => <Skeleton circle />);
        expect(container.querySelector(".skeleton.skeleton-circle")).not.toBeNull();
    });
});

describe("SkeletonText", () => {
    it("renders 3 lines by default inside a .skeleton-text container", () => {
        const { container } = render(() => <SkeletonText />);
        expect(container.querySelector(".skeleton-text")).not.toBeNull();
        expect(container.querySelectorAll(".skeleton-text .skeleton")).toHaveLength(3);
    });

    it("renders the requested number of lines", () => {
        const { container } = render(() => <SkeletonText lines={5} />);
        expect(container.querySelectorAll(".skeleton-text .skeleton")).toHaveLength(5);
    });
});

describe("SkeletonTable", () => {
    it("renders rows × columns skeleton cells", () => {
        const { container } = render(() => <SkeletonTable columns={4} rows={3} />);
        expect(container.querySelectorAll("tbody tr")).toHaveLength(3);
        expect(container.querySelectorAll("tbody .skeleton")).toHaveLength(12);
    });
});

describe("SkeletonHeader", () => {
    it("renders a .page-header with a title bar and one subtitle line by default", () => {
        const { container } = render(() => <SkeletonHeader />);
        expect(container.querySelector(".page-header .page-header-row")).not.toBeNull();
        // 1 title bar + 1 subtitle line
        expect(container.querySelectorAll(".skeleton")).toHaveLength(2);
    });

    it("honors subtitleLines", () => {
        const { container } = render(() => <SkeletonHeader subtitleLines={3} />);
        // 1 title bar + 3 subtitle lines
        expect(container.querySelectorAll(".skeleton")).toHaveLength(4);
    });
});

describe("SkeletonCard", () => {
    it("renders a title bar plus body text lines", () => {
        const { container } = render(() => <SkeletonCard lines={4} />);
        expect(container.querySelector(".card.skeleton-card")).not.toBeNull();
        // 1 title bar + 4 body lines
        expect(container.querySelectorAll(".skeleton")).toHaveLength(5);
    });
});
