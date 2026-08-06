// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { Router } from "@solidjs/router";
import { render } from "@solidjs/testing-library";
import { VersionsTab } from "./VersionsTab";
import type { ArtifactVersionSummary } from "~/api/client";

const version: ArtifactVersionSummary = {
    versionKey: "v1.2.3",
    sbomId: "11111111-1111-1111-1111-111111111111",
    sbomCount: 1,
    createdAt: "2026-01-01T00:00:00Z",
    architectures: null,
    signingStatus: "unsigned",
    sufficient: true,
};

function renderTab(isContainer: boolean) {
    return render(() => (
        <Router
            root={(props) => <>{props.children}</>}
        >
            {[
                {
                    path: "/",
                    component: () => (
                        <VersionsTab
                            artifactId="22222222-2222-2222-2222-222222222222"
                            isContainer={isContainer}
                            versions={[version]}
                            pagination={undefined}
                            loading={false}
                            isError={false}
                            onPageChange={() => undefined}
                        />
                    ),
                },
            ]}
        </Router>
    ));
}

describe("VersionsTab column gating", () => {
    it("shows architecture and signing for a container", () => {
        const { getByText } = renderTab(true);
        expect(getByText("Architectures")).toBeDefined();
        expect(getByText("Signing")).toBeDefined();
    });

    // A binary or library has neither an architecture list nor a cosign
    // signature, so those columns would be a stripe of em-dashes (ocidex-rj4.3).
    it("omits architecture and signing for a non-container", () => {
        const { queryByText, getByText } = renderTab(false);
        expect(queryByText("Architectures")).toBeNull();
        expect(queryByText("Signing")).toBeNull();
        // Type-agnostic columns survive.
        expect(getByText("Version")).toBeDefined();
        expect(getByText("Build Date")).toBeDefined();
    });
});
