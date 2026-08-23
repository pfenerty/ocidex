// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { createSignal } from "solid-js";
import { render } from "@solidjs/testing-library";
import DataTable from "./DataTable";
import type { Column } from "./DataTable";

interface Row {
    name: string;
}

const columns: Column<Row>[] = [
    { header: "Name", render: (r) => <span>{r.name}</span> },
    { header: "Kind", render: () => <span>kind</span> },
];

describe("DataTable first load", () => {
    it("renders real headers + skeleton rows and no spinner", () => {
        const { container, getByText } = render(() => (
            <DataTable
                columns={columns}
                rows={undefined}
                loading={true}
                isError={false}
                emptyTitle="Nothing here"
                skeletonRows={3}
            />
        ));
        // Real headers are present immediately.
        expect(getByText("Name")).toBeDefined();
        expect(getByText("Kind")).toBeDefined();
        // 3 rows × 2 columns of shimmer cells.
        expect(container.querySelectorAll("tbody .skeleton")).toHaveLength(6);
        // No centered spinner.
        expect(container.querySelector(".loading")).toBeNull();
    });
});

describe("DataTable loaded", () => {
    it("renders real cell content, no skeletons", () => {
        const { container, getByText } = render(() => (
            <DataTable
                columns={columns}
                rows={[{ name: "alpha" }, { name: "beta" }]}
                loading={false}
                isError={false}
                emptyTitle="Nothing here"
            />
        ));
        expect(getByText("alpha")).toBeDefined();
        expect(getByText("beta")).toBeDefined();
        expect(container.querySelectorAll("tbody .skeleton")).toHaveLength(0);
    });

    it("renders the empty state when loaded with no rows", () => {
        const { getByText } = render(() => (
            <DataTable
                columns={columns}
                rows={[]}
                loading={false}
                isError={false}
                emptyTitle="Nothing here"
            />
        ));
        expect(getByText("Nothing here")).toBeDefined();
    });
});

describe("DataTable reactivity", () => {
    it("re-renders the body when the rows signal changes (pagination/sort)", () => {
        const [rows, setRows] = createSignal<Row[]>([{ name: "alpha" }]);
        const { queryByText } = render(() => (
            <DataTable
                columns={columns}
                rows={rows()}
                loading={false}
                isError={false}
                emptyTitle="Nothing here"
            />
        ));
        expect(queryByText("alpha")).not.toBeNull();
        setRows([{ name: "beta" }]);
        expect(queryByText("beta")).not.toBeNull();
        expect(queryByText("alpha")).toBeNull();
    });

    // A refetch here is a sort, a page, or a keystroke in a debounced filter.
    // Replacing the rows with shimmer for it blanked the table the reader was
    // mid-sentence in, several times per search, to announce work they had just
    // asked for themselves.
    it("keeps the rows on screen while refetching and marks the table busy", () => {
        const [loading, setLoading] = createSignal(false);
        const { container, queryByText } = render(() => (
            <DataTable
                columns={columns}
                rows={[{ name: "alpha" }]}
                loading={loading()}
                isError={false}
                emptyTitle="Nothing here"
            />
        ));
        const card = container.querySelector(".card");
        expect(card?.getAttribute("aria-busy")).toBe("false");

        setLoading(true);

        expect(queryByText("alpha")).not.toBeNull();
        expect(container.querySelectorAll("tbody .skeleton")).toHaveLength(0);
        // The state is on the element rather than only in a class, so a screen
        // reader gets it too instead of inferring it from content vanishing.
        expect(card?.getAttribute("aria-busy")).toBe("true");
        expect(card?.classList.contains("table-refetching")).toBe(true);
    });

    // First load is the one case with nothing to keep, so it still shimmers.
    it("still shimmers on first load, when there are no rows to keep", () => {
        const { container } = render(() => (
            <DataTable
                columns={columns}
                rows={undefined}
                loading={true}
                isError={false}
                emptyTitle="Nothing here"
            />
        ));
        expect(container.querySelectorAll("tbody .skeleton").length).toBeGreaterThan(0);
    });
});

describe("DataTable caption", () => {
    const withCaption = (rows: Row[] | undefined, isError: boolean) =>
        render(() => (
            <DataTable
                columns={columns}
                rows={rows}
                loading={false}
                isError={isError}
                error={isError ? new Error("boom") : undefined}
                emptyTitle="Nothing here"
                caption={<h3>Recent drift</h3>}
                class="mt-6"
            />
        ));

    it("renders above the table, inside the same card", () => {
        const { container } = withCaption([{ name: "a" }], false);
        const card = container.querySelector(".card");
        expect(card).not.toBeNull();
        expect(card?.classList.contains("mt-6")).toBe(true);
        // The caption is the card's first child, ahead of the table wrapper.
        expect(card?.firstElementChild?.tagName).toBe("H3");
        expect(card?.querySelector(".table-wrapper")).not.toBeNull();
    });

    it("survives the empty state, which is when it matters most", () => {
        // A feed that says "nothing recorded" without the sentence explaining
        // what it records is a blank the reader has to guess at.
        const { container, getByText } = withCaption([], false);
        expect(getByText("Nothing here")).toBeDefined();
        expect(container.querySelector(".card > h3")).not.toBeNull();
        expect(container.querySelector("table")).toBeNull();
    });

    it("survives the error state", () => {
        const { container } = withCaption(undefined, true);
        expect(container.querySelector(".card > h3")).not.toBeNull();
    });

    it("is absent by default, leaving the bare states every caller already has", () => {
        const { container } = render(() => (
            <DataTable
                columns={columns}
                rows={[]}
                loading={false}
                isError={false}
                emptyTitle="Nothing here"
            />
        ));
        expect(container.querySelector(".card")).toBeNull();
    });
});

describe("DataTable rows", () => {
    const rows: Row[] = [{ name: "a" }, { name: "b" }, { name: "c" }];

    function renderRows(props: Partial<Parameters<typeof DataTable<Row>>[0]> = {}) {
        return render(() => (
            <DataTable
                columns={columns}
                rows={rows}
                loading={false}
                isError={false}
                emptyTitle="Nothing here"
                {...props}
            />
        ));
    }

    it("keeps rowClass and row-clickable on the same row", () => {
        // Solid sets className first and then diffs classList against its own
        // previous state, so `class` beside `classList` wipes the classList
        // entry. The row kept its tabindex and lost its pointer cursor — a
        // clickable row that does not look clickable.
        const { container } = renderRows({
            onRowClick: () => undefined,
            rowClass: (r) => (r.name === "b" ? "row-muted" : undefined),
        });
        const trs = [...container.querySelectorAll("tbody tr")];
        expect(trs.map((tr) => tr.className)).toEqual([
            "row-clickable",
            "row-muted row-clickable",
            "row-clickable",
        ]);
        expect(trs[0].getAttribute("tabindex")).toBe("0");
    });

    it("offers no tab stop on a row rowClickable excludes", () => {
        const { container } = renderRows({
            onRowClick: () => undefined,
            rowClickable: (r) => r.name !== "b",
        });
        const trs = [...container.querySelectorAll("tbody tr")];
        expect(trs[1].className).toBe("");
        expect(trs[1].getAttribute("tabindex")).toBeNull();
        expect(trs[0].getAttribute("tabindex")).toBe("0");
    });

    it("activates a row from the keyboard, not only the mouse", () => {
        const seen: string[] = [];
        const { container } = renderRows({ onRowClick: (r) => seen.push(r.name) });
        const tr = container.querySelector("tbody tr");
        if (tr === null) throw new Error("no rows rendered");
        tr.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
        tr.dispatchEvent(new KeyboardEvent("keydown", { key: " ", bubbles: true }));
        tr.dispatchEvent(new KeyboardEvent("keydown", { key: "x", bubbles: true }));
        expect(seen).toEqual(["a", "a"]);
    });

    it("labels each run of equal keys once", () => {
        const { container } = renderRows({
            rows: [{ name: "a" }, { name: "a" }, { name: "b" }],
            groupBy: { key: (r) => r.name, header: (key, count) => `${key} (${count})` },
        });
        const headers = [...container.querySelectorAll("tr.group-header-row td")];
        expect(headers.map((td) => td.textContent)).toEqual(["a (2)", "b (1)"]);
        expect(headers[0].getAttribute("colspan")).toBe("2");
        expect(container.querySelectorAll("tbody tr")).toHaveLength(5);
    });

    it("applies a column class to its header and to every cell", () => {
        const { container } = renderRows({
            columns: [
                { header: "Name", class: "truncate", render: (r) => <span>{r.name}</span> },
                { header: "Kind", align: "right", render: () => <span>kind</span> },
            ],
        });
        expect(container.querySelector("thead th")?.className).toContain("truncate");
        expect(
            [...container.querySelectorAll("tbody td:first-child")].every((td) =>
                td.className.includes("truncate"),
            ),
        ).toBe(true);
        expect(container.querySelectorAll("thead th")[1].className).toContain("text-right");
    });

    it("drops the card in bare mode, for a table already inside one", () => {
        const { container } = renderRows({ bare: true });
        expect(container.querySelector(".card")).toBeNull();
        expect(container.querySelector(".table-wrapper table")).not.toBeNull();
    });
});

describe("DataTable mobile layout", () => {
    it("labels each cell from its column header, for the card stack", () => {
        // Below 768px the header row is hidden and each cell names itself from
        // `data-label`. happy-dom has no layout engine, so what is asserted here
        // is the contract the CSS depends on; the rendering itself was checked
        // in a browser at 500px.
        const { container } = render(() => (
            <DataTable
                columns={columns}
                rows={[{ name: "alpha" }]}
                loading={false}
                isError={false}
                emptyTitle="Nothing here"
            />
        ));
        const labels = [...container.querySelectorAll("tbody td")].map((td) =>
            td.getAttribute("data-label"),
        );
        expect(labels).toEqual(["Name", "Kind"]);
    });

    it("labels the skeleton cells too, so first load stacks like the rows will", () => {
        const { container } = render(() => (
            <DataTable
                columns={columns}
                rows={undefined}
                loading={true}
                isError={false}
                emptyTitle="Nothing here"
                skeletonRows={1}
            />
        ));
        const labels = [...container.querySelectorAll("tbody td")].map((td) =>
            td.getAttribute("data-label"),
        );
        expect(labels).toEqual(["Name", "Kind"]);
    });

    it("takes mobileLabel when the header is not a string", () => {
        // One column in the app renders a coloured `<span>` as its header, and
        // `attr(data-label)` cannot read a JSX element.
        const jsx: Column<Row>[] = [
            { header: <span>Kind</span>, mobileLabel: "Kind", render: () => <span>k</span> },
            { header: <span>State</span>, render: () => <span>s</span> },
        ];
        const { container } = render(() => (
            <DataTable
                columns={jsx}
                rows={[{ name: "alpha" }]}
                loading={false}
                isError={false}
                emptyTitle="Nothing here"
            />
        ));
        const cells = [...container.querySelectorAll("tbody td")];
        expect(cells[0].getAttribute("data-label")).toBe("Kind");
        // No label rather than a wrong one: the cell spans the card instead of
        // sitting beside an empty gutter.
        expect(cells[1].hasAttribute("data-label")).toBe(false);
    });

    it("leaves an actions column unlabelled", () => {
        // `header: ""` is how the app spells "this column is a control, not a
        // field" — there is nothing to name it.
        const withActions: Column<Row>[] = [
            ...columns,
            { header: "", render: () => <button>Edit</button> },
        ];
        const { container } = render(() => (
            <DataTable
                columns={withActions}
                rows={[{ name: "alpha" }]}
                loading={false}
                isError={false}
                emptyTitle="Nothing here"
            />
        ));
        const cells = [...container.querySelectorAll("tbody td")];
        expect(cells[2].hasAttribute("data-label")).toBe(false);
    });

    it("stacks into cards by default", () => {
        const { container } = render(() => (
            <DataTable
                columns={columns}
                rows={[{ name: "alpha" }]}
                loading={false}
                isError={false}
                emptyTitle="Nothing here"
            />
        ));
        const wrapper = container.querySelector(".table-wrapper");
        expect(wrapper?.classList.contains("table-mobile-cards")).toBe(true);
        expect(wrapper?.classList.contains("table-mobile-scroll")).toBe(false);
    });

    it("keeps the grid and scrolls it when the caller opts out", () => {
        // The two tree views and the enricher health matrix: their meaning is
        // the grid, and the scroll is the wrapper's, never the page body's.
        const { container } = render(() => (
            <DataTable
                columns={columns}
                rows={[{ name: "alpha" }]}
                loading={false}
                isError={false}
                emptyTitle="Nothing here"
                mobileLayout="scroll"
            />
        ));
        const wrapper = container.querySelector(".table-wrapper");
        expect(wrapper?.classList.contains("table-mobile-scroll")).toBe(true);
        expect(wrapper?.classList.contains("table-mobile-cards")).toBe(false);
    });
});
