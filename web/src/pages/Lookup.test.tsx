// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { Router, Route } from "@solidjs/router";
import { render, waitFor } from "@solidjs/testing-library";
import { APIClientError } from "~/api/client";
import { useArtifactLookup, useSBOMLookup } from "~/api/queries/lookup";
import type * as LookupQueries from "~/api/queries/lookup";
import { ArtifactLookup, SBOMLookup } from "~/pages/Lookup";
import { artifactLookupPath } from "~/components/CopyShareLink";

// Only the two fetching hooks are stubbed — conflictCandidates and isNotFound
// are the logic under test on the error paths, so they run for real.
vi.mock("~/api/queries/lookup", async (importOriginal) => ({
    ...(await importOriginal<typeof LookupQueries>()),
    useArtifactLookup: vi.fn(),
    useSBOMLookup: vi.fn(),
}));

const mockArtifactLookup = vi.mocked(useArtifactLookup);
const mockSBOMLookup = vi.mocked(useSBOMLookup);

function queryState(over: Partial<{ isLoading: boolean; isError: boolean; error: unknown; data: unknown }>) {
    return { isLoading: false, isError: false, error: null, data: undefined, ...over } as never;
}

// The resolver navigates, so the destination route has to exist for the
// assertion to mean anything more than "the URL string changed".
function renderAt(path: string) {
    window.history.replaceState({}, "", path);
    return render(() => (
        <Router root={(props) => <>{props.children}</>}>
            <Route path="/artifacts/lookup" component={ArtifactLookup} />
            <Route path="/sboms/lookup" component={SBOMLookup} />
            <Route path="/artifacts/:id" component={() => <div>artifact detail</div>} />
            <Route path="/sboms/:id" component={() => <div>sbom detail</div>} />
        </Router>
    ));
}

describe("ArtifactLookup", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockSBOMLookup.mockReturnValue(queryState({}));
    });

    it("replaces itself with the canonical route on a unique match", async () => {
        mockArtifactLookup.mockReturnValue(queryState({ data: { id: "art-1" } }));

        const { getByText } = renderAt("/artifacts/lookup?name=myapp");

        await waitFor(() => {
            expect(window.location.pathname).toBe("/artifacts/art-1");
        });
        expect(getByText("artifact detail")).toBeTruthy();
    });

    it("passes the qualifiers through to the lookup", () => {
        mockArtifactLookup.mockReturnValue(queryState({}));

        renderAt("/artifacts/lookup?name=myapp&type=container&group=acme");

        const params = mockArtifactLookup.mock.calls[0][0]();
        expect(params.name).toBe("myapp");
        expect(params.type).toBe("container");
        expect(params.group).toBe("acme");
    });

    it("round-trips a link emitted by the copy-link control", async () => {
        mockArtifactLookup.mockReturnValue(queryState({ data: { id: "art-1" } }));

        renderAt(
            artifactLookupPath({
                name: "ghcr.io/pfenerty/ocidex",
                type: "container",
                group: "pfenerty",
            }),
        );

        const params = mockArtifactLookup.mock.calls[0][0]();
        expect(params.name).toBe("ghcr.io/pfenerty/ocidex");
        expect(params.type).toBe("container");
        expect(params.group).toBe("pfenerty");
        await waitFor(() => {
            expect(window.location.pathname).toBe("/artifacts/art-1");
        });
    });

    it("renders the candidates instead of navigating on 409", () => {
        mockArtifactLookup.mockReturnValue(
            queryState({
                isError: true,
                error: new APIClientError(409, {
                    status: 409,
                    title: "Ambiguous lookup",
                    detail: "2 visible artifact candidates match",
                    candidates: [
                        { id: "art-1", qualifiers: { type: "container" } },
                        { id: "art-2", qualifiers: { type: "application" } },
                    ],
                }),
            }),
        );

        const { getByText, container } = renderAt("/artifacts/lookup?name=myapp");

        expect(window.location.pathname).toBe("/artifacts/lookup");
        expect(getByText("Multiple matches")).toBeTruthy();
        const links = [...container.querySelectorAll("a")].map((a) => a.getAttribute("href"));
        expect(links).toEqual(["/artifacts/art-1", "/artifacts/art-2"]);
        expect(getByText("type: container")).toBeTruthy();
    });

    it("disambiguates a bare name from the palette instead of failing", () => {
        // The command palette offers "Resolve artifact <term>" with nothing but
        // the name — the ladder's first rung — so ambiguity is the expected
        // outcome, not an edge case. It has to land somewhere useful.
        mockArtifactLookup.mockReturnValue(
            queryState({
                isError: true,
                error: new APIClientError(409, {
                    status: 409,
                    title: "Ambiguous lookup",
                    detail: "3 visible artifact candidates match",
                    candidates: [
                        { id: "art-1", qualifiers: { group: "pfenerty" } },
                        { id: "art-2", qualifiers: { group: "acme" } },
                        { id: "art-3", qualifiers: { group: "example" } },
                    ],
                }),
            }),
        );

        const { getByText, container } = renderAt(
            artifactLookupPath({ name: "ghcr.io/pfenerty/ocidex" }),
        );

        // The name survived the slashes, and the page offers the three rather
        // than reporting a failure.
        expect(mockArtifactLookup.mock.calls[0][0]().name).toBe("ghcr.io/pfenerty/ocidex");
        expect(getByText("Multiple matches")).toBeTruthy();
        expect(container.querySelectorAll("a")).toHaveLength(3);
        expect(getByText("group: acme")).toBeTruthy();
    });

    it("renders NotFound on 404", () => {
        mockArtifactLookup.mockReturnValue(
            queryState({ isError: true, error: new APIClientError(404, { status: 404, detail: "artifact not found" }) }),
        );

        const { getByText } = renderAt("/artifacts/lookup?name=nope");

        expect(getByText("Page not found")).toBeTruthy();
    });

    it("explains what is missing when name is absent", () => {
        mockArtifactLookup.mockReturnValue(queryState({}));

        const { getByText } = renderAt("/artifacts/lookup");

        expect(getByText("Incomplete lookup")).toBeTruthy();
    });
});

describe("SBOMLookup", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockArtifactLookup.mockReturnValue(queryState({}));
    });

    it("resolves the digest form to the canonical route", async () => {
        mockSBOMLookup.mockReturnValue(queryState({ data: { id: "sbom-1" } }));

        renderAt("/sboms/lookup?digest=sha256:abc");

        await waitFor(() => {
            expect(window.location.pathname).toBe("/sboms/sbom-1");
        });
    });

    it("passes the ladder qualifiers through to the lookup", () => {
        mockSBOMLookup.mockReturnValue(queryState({}));

        renderAt("/sboms/lookup?artifact=myapp&version=1.2.3&arch=amd64&flavor=alpine");

        // Read before any navigation: the accessor reflects the *current* URL,
        // so a resolved lookup would have already cleared these.
        const params = mockSBOMLookup.mock.calls[0][0]();
        expect(params.artifact).toBe("myapp");
        expect(params.version).toBe("1.2.3");
        expect(params.arch).toBe("amd64");
        expect(params.flavor).toBe("alpine");
    });

    it("treats artifact without version as an incomplete lookup", () => {
        mockSBOMLookup.mockReturnValue(queryState({}));

        const { getByText } = renderAt("/sboms/lookup?artifact=myapp");

        expect(getByText("Incomplete lookup")).toBeTruthy();
    });
});
