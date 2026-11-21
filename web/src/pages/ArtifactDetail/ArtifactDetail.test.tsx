// @vitest-environment happy-dom
import { describe, it, expect, vi } from "vitest";
import { Router, Route } from "@solidjs/router";
import { render } from "@solidjs/testing-library";
import type * as SearchModule from "~/api/queries/search";

vi.mock("~/api/queries/search", async (importOriginal) => ({
    ...(await importOriginal<typeof SearchModule>()),
    useArtifactSearch: () => ({ data: undefined }),
}));

import ArtifactDetail from "./index";

describe("ArtifactDetail", () => {
    // The API answers 422 for an id that is not a UUID, which the page used to
    // render raw as "Unprocessable Entity".
    it("renders the not-found page for an id that is not a UUID", () => {
        window.history.replaceState({}, "", "/artifacts/pyhton");
        const { container } = render(() => (
            <Router>
                <Route path="/artifacts/:id" component={ArtifactDetail} />
            </Router>
        ));
        expect(container.querySelector("h2")?.textContent).toBe("A wild 404 appeared.");
        expect(container.textContent).toContain("/artifacts/pyhton");
    });
});
