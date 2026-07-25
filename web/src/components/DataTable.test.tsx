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

    it("swaps to skeleton rows when loading flips true with rows present (refetch)", () => {
        const [loading, setLoading] = createSignal(false);
        const { container } = render(() => (
            <DataTable
                columns={columns}
                rows={[{ name: "alpha" }]}
                loading={loading()}
                isError={false}
                emptyTitle="Nothing here"
            />
        ));
        expect(container.querySelectorAll("tbody .skeleton")).toHaveLength(0);
        setLoading(true);
        expect(container.querySelectorAll("tbody .skeleton").length).toBeGreaterThan(0);
    });
});
