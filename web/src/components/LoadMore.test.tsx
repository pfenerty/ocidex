// @vitest-environment happy-dom
import { describe, it, expect, vi } from "vitest";
import { render } from "@solidjs/testing-library";
import LoadMore from "./LoadMore";
import Pagination from "./Pagination";
import DataTable from "./DataTable";
import type { Column } from "./DataTable";

const renderLoadMore = (props: Partial<Parameters<typeof LoadMore>[0]> = {}) =>
    render(() => (
        <LoadMore hasMore={true} loading={false} onClick={() => undefined} loaded={40} {...props} />
    ));

describe("LoadMore as Pagination's sibling", () => {
    // The two footers used to be different shapes: Pagination a space-between
    // row with a count on the left, LoadMore a centred lone button that said
    // nothing about how far into the list you were.
    it("emits the same footer row as Pagination, with the count on the left", () => {
        const { container } = renderLoadMore();
        const footer = container.querySelector(".pagination");
        expect(footer).not.toBeNull();
        // No inline centring override — the shared class decides the layout.
        expect(footer?.getAttribute("style")).toBeNull();
        expect(footer?.firstElementChild?.tagName).toBe("SPAN");
        expect(footer?.firstElementChild?.textContent).toBe("Showing 40");
        expect(footer?.querySelector(".pagination-controls")).not.toBeNull();
    });

    it("matches Pagination's element structure", () => {
        const a = renderLoadMore().container.querySelector(".pagination");
        const b = render(() => (
            <Pagination
                pagination={{ total: 57, limit: 50, offset: 0 }}
                onPageChange={() => undefined}
            />
        )).container.querySelector(".pagination");
        const shape = (el: Element | null) =>
            [...(el?.children ?? [])].map((c) => `${c.tagName  }.${  c.className}`);
        expect(shape(a)).toEqual(shape(b));
    });

    // Reaching the end of a list is information, not an absence. The footer
    // used to disappear entirely, so the page jumped on the last "Load more".
    it("keeps the footer and the count when there is nothing more to load", () => {
        const { container, queryByText } = renderLoadMore({ hasMore: false, loaded: 40 });
        expect(container.querySelector(".pagination")).not.toBeNull();
        expect(queryByText("Load more")).toBeNull();
        expect(container.querySelector(".pagination span")?.textContent).toBe("Showing 40 of 40");
    });

    // A keyset response carries no total, so the count must not imply one while
    // pages remain — "Showing 40 of 40" is only true once hasMore is false.
    it("claims a total only once the list is exhausted", () => {
        const more = renderLoadMore({ hasMore: true, loaded: 40 });
        expect(more.container.querySelector("span")?.textContent).toBe("Showing 40");
    });

    it("says No results rather than Showing 0", () => {
        const { container } = renderLoadMore({ hasMore: false, loaded: 0 });
        expect(container.querySelector(".pagination span")?.textContent).toBe("No results");
    });

    it("omits the count when the caller has none to give", () => {
        // Rendered directly rather than through the helper: Solid's prop spread
        // does not let an explicit `undefined` override an earlier value.
        const { container } = render(() => (
            <LoadMore hasMore={true} loading={false} onClick={() => undefined} />
        ));
        expect(container.querySelector(".pagination span")?.textContent).toBe("");
        expect(container.querySelector(".pagination")).not.toBeNull();
    });
});

describe("DataTable keyset footer", () => {
    interface Row {
        name: string;
    }
    const columns: Column<Row>[] = [{ header: "Name", render: (r) => <span>{r.name}</span> }];

    it("counts the rows it is showing, so the caller passes no total", () => {
        const { container } = render(() => (
            <DataTable
                columns={columns}
                rows={[{ name: "a" }, { name: "b" }, { name: "c" }]}
                loading={false}
                isError={false}
                emptyTitle="Nothing here"
                loadMore={{ hasMore: true, loading: false, onClick: vi.fn() }}
            />
        ));
        expect(container.querySelector(".pagination span")?.textContent).toBe("Showing 3");
    });
});
