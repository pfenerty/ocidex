// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { Router, Route } from "@solidjs/router";
import { render } from "@solidjs/testing-library";
import { LicensesTab } from "./LicensesTab";
import type { LicenseCount } from "~/api/client";

const gpl: LicenseCount = { id: "l1", spdxId: "GPL-2.0-only", name: "GPL 2.0", componentCount: 3, category: "copyleft" };

function renderTab() {
    return render(() => (
        <Router root={(p) => <>{p.children}</>}>
            <Route
                path="*"
                component={() => (
                    <LicensesTab licenses={[gpl]} sbomId="s1" subjectVersion="v1.6.0" loading={false} isError={false} />
                )}
            />
        </Router>
    ));
}

// ocidex-nps9.29: no scope, and a red error banner for ordinary copyleft.
describe("LicensesTab", () => {
    it("names the SBOM it counts", () => {
        const { container } = renderTab();
        expect(container.textContent).toContain("most recently ingested SBOM, v1.6.0");
        expect(container.querySelector('a[href="/sboms/s1"]')).not.toBeNull();
    });

    it("notes copyleft as information, not an error", () => {
        const { container } = renderTab();
        expect(container.querySelector(".alert-danger")).toBeNull();
        expect(container.querySelector(".alert-info")?.textContent).toContain("copyleft");
        expect(container.textContent).toContain("(3 components)");
    });
});
