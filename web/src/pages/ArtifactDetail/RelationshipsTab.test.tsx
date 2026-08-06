// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { Router } from "@solidjs/router";
import { render } from "@solidjs/testing-library";
import { RelationshipsTab } from "./RelationshipsTab";
import type { ArtifactRelation } from "~/api/client";

function relation(over: Partial<ArtifactRelation> = {}): ArtifactRelation {
    return {
        artifactId: "11111111-1111-1111-1111-111111111111",
        artifactType: "container",
        artifactName: "ghcr.io/pfenerty/ocidex-api",
        sbomId: "22222222-2222-2222-2222-222222222222",
        subjectVersion: "v0.9.0",
        matchedVersion: "v1.2.3",
        currentVersion: "v1.2.3",
        isCurrent: true,
        ...over,
    };
}

function renderTab(relations: ArtifactRelation[]) {
    return render(() => (
        <Router root={(props) => <>{props.children}</>}>
            {[
                {
                    path: "/",
                    component: () => (
                        <RelationshipsTab
                            artifactName="ocidex"
                            relations={relations}
                            loading={false}
                            isError={false}
                        />
                    ),
                },
            ]}
        </Router>
    ));
}

describe("RelationshipsTab", () => {
    it("renders usages with per-consumer versions", () => {
        const { getByText } = renderTab([relation()]);
        expect(getByText("ghcr.io/pfenerty/ocidex-api")).toBeDefined();
        expect(getByText("v1.2.3")).toBeDefined();
        expect(getByText(/ships in/)).toBeDefined();
    });

    it("marks a consumer carrying an older build as outdated", () => {
        const { getByText } = renderTab([
            relation({ matchedVersion: "v1.2.1", isCurrent: false }),
        ]);
        expect(getByText(/Outdated/)).toBeDefined();
        // The current version is named on the card so the drift is actionable
        // without opening the consumer.
        expect(getByText(/current is v1.2.3/)).toBeDefined();
        expect(getByText(/1 outdated/)).toBeDefined();
    });

    it("says nothing loud when every consumer is current", () => {
        const { getByText, queryByText } = renderTab([relation()]);
        expect(getByText("Up to date")).toBeDefined();
        expect(queryByText(/Outdated/)).toBeNull();
        expect(queryByText(/outdated/)).toBeNull();
    });

    // isCurrent is absent when either side has no comparable version; reporting
    // that as "up to date" would be a false all-clear (ocidex-rj4.4).
    it("distinguishes unknown drift from up to date", () => {
        const { getByText, queryByText } = renderTab([
            relation({ isCurrent: undefined, currentVersion: undefined }),
        ]);
        expect(getByText("Version unknown")).toBeDefined();
        expect(queryByText("Up to date")).toBeNull();
        expect(queryByText(/Outdated/)).toBeNull();
    });

    it("sorts drifted consumers above current ones", () => {
        const { container } = renderTab([
            relation({
                artifactId: "aaaa",
                artifactName: "current-image",
                isCurrent: true,
            }),
            relation({
                artifactId: "bbbb",
                artifactName: "behind-image",
                matchedVersion: "v1.0.0",
                isCurrent: false,
            }),
        ]);
        const names = [...container.querySelectorAll("a")]
            .map((a) => a.textContent)
            .filter((t) => t.endsWith("-image"));
        expect(names[0]).toBe("behind-image");
        expect(names[1]).toBe("current-image");
    });

    it("shows an empty state when nothing ships this artifact", () => {
        const { getByText } = renderTab([]);
        expect(getByText("Not shipped anywhere yet")).toBeDefined();
    });
});
