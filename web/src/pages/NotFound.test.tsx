// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { Router, Route } from "@solidjs/router";
import { render } from "@solidjs/testing-library";
import NotFound from "./NotFound";

// ocidex-nps9.30: the button said "Back to Dashboard", led Home, and the router
// marked it active on every path, which painted it blue.
describe("NotFound", () => {
    it("offers a primary, never-active link Home", () => {
        window.history.replaceState({}, "", "/no-such-page");
        const { container } = render(() => (
            <Router>
                <Route path="*" component={NotFound} />
            </Router>
        ));
        const link = container.querySelector('a[href="/"]');
        expect(link?.textContent.trim()).toBe("Back to Home");
        expect(link?.className).toContain("btn-primary");
        expect(link?.classList.contains("active")).toBe(false);
    });
});
