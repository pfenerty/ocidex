// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { Router, Route } from "@solidjs/router";
import { render } from "@solidjs/testing-library";
import type * as SearchModule from "~/api/queries/search";

const searchData = vi.hoisted(() => ({ value: undefined as { label: string; path: string }[] | undefined }));
const searchedFor = vi.hoisted(() => ({ value: "" }));

vi.mock("~/api/queries/search", async (importOriginal) => ({
    ...(await importOriginal<typeof SearchModule>()),
    useArtifactSearch: (term: () => string) => ({
        get data() {
            searchedFor.value = term();
            return term() === "" ? undefined : searchData.value;
        },
    }),
}));

import NotFound from "./NotFound";

function renderAt(path: string) {
    window.history.replaceState({}, "", path);
    return render(() => (
        <Router>
            <Route path="*" component={NotFound} />
        </Router>
    ));
}

beforeEach(() => {
    searchData.value = undefined;
    searchedFor.value = "";
});

describe("NotFound", () => {
    // The router used to mark "/" active on every path, which painted it.
    it("offers a never-active link home", () => {
        const { container } = renderAt("/no-such-page");
        const link = container.querySelector('a[href="/"]');
        expect(link?.textContent.trim()).toBe("Back to home");
        expect(link?.classList.contains("active")).toBe(false);
    });

    it("says what was not found", () => {
        const { container } = renderAt("/artifacts/pyhton");
        expect(container.querySelector("h2")?.textContent).toBe("A wild 404 appeared.");
        expect(container.textContent).toContain("Nothing is indexed at /artifacts/pyhton.");
    });

    it("suggests the closest artifact by the last path segment", () => {
        searchData.value = [{ label: "registry-1.docker.io/library/python", path: "/artifacts/abc" }];
        const { container } = renderAt("/artifacts/pyhton");
        expect(searchedFor.value).toBe("pyhton");
        const hint = container.querySelector('a[href="/artifacts/abc"]');
        expect(hint?.textContent).toBe("registry-1.docker.io/library/python");
    });

    it("does not search for an id", () => {
        renderAt("/artifacts/3e671687-395b-41f5-a30f-a58921a69b79");
        expect(searchedFor.value).toBe("");
    });
});
