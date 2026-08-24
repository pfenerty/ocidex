// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { render } from "@solidjs/testing-library";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
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

    it("adds the inline modifier when inline is set", () => {
        const { container } = render(() => <Skeleton inline />);
        expect(container.querySelector(".skeleton.skeleton-inline")).not.toBeNull();
    });
});

describe("Skeleton inline flow", () => {
    // A page title's placeholder stands in for one word inside a heading, so it
    // has to flow with the text. The obvious spelling — a Tailwind
    // `inline-block` on the call site — is inert here, because `.skeleton`
    // below is unlayered and unlayered CSS outranks `@layer utilities`
    // regardless of source order. Five call sites shipped exactly that dead
    // class during ocidex-ag4q.18. This asserts the modifier has a counterpart
    // in the stylesheet, the way fontContract and typeScale do.
    const css = readFileSync(resolve(__dirname, "./Skeleton.css"), "utf8")
        .replace(/\/\*[\s\S]*?\*\//g, "");

    it("defines .skeleton-inline as inline-block", () => {
        expect(/\.skeleton-inline\s*\{[^}]*display:\s*inline-block/.test(css)).toBe(true);
    });

    it("keeps .skeleton out of a cascade layer so the modifier can win", () => {
        // If `.skeleton` ever moves into a layer, `.skeleton-inline` must move
        // with it — otherwise this pairing silently inverts.
        expect(css).not.toMatch(/@layer/);
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

describe("SkeletonTable headers", () => {
    it("renders a <thead> with the given labels and derives column count", () => {
        const { container, getByText } = render(() => (
            <SkeletonTable headers={["Name", "Type", "Version"]} rows={2} />
        ));
        expect(getByText("Name")).toBeDefined();
        expect(getByText("Type")).toBeDefined();
        expect(container.querySelectorAll("thead th")).toHaveLength(3);
        // 2 rows × 3 derived columns of shimmer cells
        expect(container.querySelectorAll("tbody .skeleton")).toHaveLength(6);
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
