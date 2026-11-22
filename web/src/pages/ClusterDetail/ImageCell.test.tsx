// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { Router, Route } from "@solidjs/router";
import { render } from "@solidjs/testing-library";
import { ImageCell } from "./WorkloadsTab";

function renderCell(matchState: string) {
    return render(() => (
        <Router>
            <Route path="*" component={() => <ImageCell row={{ imageRef: "ghcr.io/acme/billing-worker:1.2", matchState }} />} />
        </Router>
    ));
}

describe("ImageCell", () => {
    it("draws a seen-only image as a silhouette with the way to index it", () => {
        const { container } = renderCell("unknown");
        expect(container.querySelector(".inventory-silhouette")).not.toBeNull();
        expect(container.querySelector(".silhouette-sprite")?.textContent).toBe("?");
        expect(container.querySelector('a[href*="tab=gaps"]')?.textContent).toBe("Index it");
        // The name stays readable: an operations table has to say what is running.
        expect(container.textContent).toContain("billing-worker");
    });

    it("draws a matched image plainly", () => {
        const { container } = renderCell("exact");
        expect(container.querySelector(".inventory-silhouette")).toBeNull();
    });
});
