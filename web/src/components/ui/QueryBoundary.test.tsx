// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { render } from "@solidjs/testing-library";
import { QueryBoundary } from "./QueryBoundary";

interface Data {
    versions: string[];
}

function boundary(query: {
    isLoading: boolean;
    isError: boolean;
    error: unknown;
    data: Data | undefined;
}) {
    return render(() => (
        <QueryBoundary
            query={query}
            loading={<p>skeleton</p>}
            empty={<p>nothing here</p>}
            when={(d) => d.versions.length > 0}
        >
            {(d) => <p>{d().versions.join(",")}</p>}
        </QueryBoundary>
    ));
}

describe("QueryBoundary", () => {
    it("shows the loading slot first", () => {
        const { container } = boundary({ isLoading: true, isError: false, error: null, data: undefined });
        expect(container.textContent).toBe("skeleton");
    });

    it("shows the error box on failure", () => {
        const { container } = boundary({
            isLoading: false,
            isError: true,
            error: new Error("boom"),
            data: undefined,
        });
        expect(container.querySelector(".error-box")?.textContent).toContain("boom");
    });

    // The bug this component exists to prevent: a query that has already
    // rendered data and then fails a refetch must show the error, not keep
    // rendering the stale body or fall back to a skeleton forever.
    it("prefers the error over stale data", () => {
        const { container } = boundary({
            isLoading: false,
            isError: true,
            error: new Error("refetch failed"),
            data: { versions: ["1.0.0"] },
        });
        expect(container.textContent).not.toContain("1.0.0");
        expect(container.querySelector(".error-box")).not.toBeNull();
    });

    it("treats a `when` miss as empty, not as data", () => {
        const { container } = boundary({ isLoading: false, isError: false, error: null, data: { versions: [] } });
        expect(container.textContent).toBe("nothing here");
    });

    it("renders children with the resolved data", () => {
        const { container } = boundary({
            isLoading: false,
            isError: false,
            error: null,
            data: { versions: ["1.0.0", "1.1.0"] },
        });
        expect(container.textContent).toBe("1.0.0,1.1.0");
    });
});
