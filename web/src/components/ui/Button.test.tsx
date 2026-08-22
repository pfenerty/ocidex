// @vitest-environment happy-dom
import { describe, it, expect, vi } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Button } from "./Button";

function btn(el: HTMLElement): HTMLElement {
    const found = el.querySelector(".btn");
    if (found === null) throw new Error("no .btn rendered");
    return found as HTMLElement;
}

describe("Button variants", () => {
    it.each([
        ["primary", "btn btn-primary"],
        ["danger", "btn btn-danger"],
        ["ghost", "btn btn-ghost"],
    ] as const)("%s emits %s", (variant, expected) => {
        const { container } = render(() => <Button variant={variant}>Go</Button>);
        expect(btn(container).className).toBe(expected);
    });

    // The bare `.btn` IS the secondary button — surface background, border, body
    // text. There is no `.btn-secondary` rule, and emitting one would be a class
    // name that silently does nothing.
    it("secondary emits the bare .btn, and is the default", () => {
        const { container: a } = render(() => <Button variant="secondary">Go</Button>);
        const { container: b } = render(() => <Button>Go</Button>);
        expect(btn(a).className).toBe("btn");
        expect(btn(b).className).toBe("btn");
    });

    it("appends size, active and caller classes in that order", () => {
        const { container } = render(() => (
            <Button variant="primary" size="sm" active class="home-band-cta">
                Go
            </Button>
        ));
        expect(btn(container).className).toBe("btn btn-primary btn-sm active home-band-cta");
    });

    it("omits btn-sm at the default size", () => {
        const { container } = render(() => <Button size="md">Go</Button>);
        expect(btn(container).className).toBe("btn");
    });
});

describe("Button disabled and loading", () => {
    it("does not fire onClick when disabled", () => {
        const onClick = vi.fn();
        const { container } = render(() => (
            <Button disabled onClick={onClick}>
                Go
            </Button>
        ));
        const el = btn(container) as HTMLButtonElement;
        expect(el.disabled).toBe(true);
        expect(el.getAttribute("aria-disabled")).toBe("true");
        fireEvent.click(el);
        expect(onClick).not.toHaveBeenCalled();
    });

    // Loading is a disabled state, not merely a decorated one: a submit button
    // that spins while still accepting clicks is how double-submits happen.
    it("loading implies disabled and renders a spinner", () => {
        const onClick = vi.fn();
        const { container } = render(() => (
            <Button loading onClick={onClick}>
                Saving
            </Button>
        ));
        const el = btn(container) as HTMLButtonElement;
        expect(el.disabled).toBe(true);
        expect(el.getAttribute("aria-busy")).toBe("true");
        expect(container.querySelector(".btn-spinner")).toBeTruthy();
        fireEvent.click(el);
        expect(onClick).not.toHaveBeenCalled();
    });

    it("marks nothing busy or disabled by default", () => {
        const { container } = render(() => <Button>Go</Button>);
        const el = btn(container) as HTMLButtonElement;
        expect(el.disabled).toBe(false);
        expect(el.getAttribute("aria-disabled")).toBeNull();
        expect(el.getAttribute("aria-busy")).toBeNull();
        expect(container.querySelector(".btn-spinner")).toBeNull();
    });
});

describe("Button as an anchor", () => {
    it("renders an <a> that keeps the href and the button classes", () => {
        const { container } = render(() => (
            <Button as="a" href="/artifacts" variant="primary" size="sm">
                Browse
            </Button>
        ));
        const el = btn(container);
        expect(el.tagName).toBe("A");
        expect(el.getAttribute("href")).toBe("/artifacts");
        expect(el.className).toBe("btn btn-primary btn-sm");
    });

    // An anchor has no `disabled` property; writing one emits an invalid
    // attribute and communicates nothing. aria-disabled is what actually reads.
    it("signals a disabled anchor through aria only", () => {
        const { container } = render(() => (
            <Button as="a" href="/x" disabled>
                Browse
            </Button>
        ));
        const el = btn(container);
        expect(el.hasAttribute("disabled")).toBe(false);
        expect(el.getAttribute("aria-disabled")).toBe("true");
    });
});

// Every class the primitive can emit must exist in the stylesheet. This is the
// `tab-btn` / `btn-secondary` failure mode: a class name that no rule matches
// renders unstyled and passes every behavioural test above.
describe("the classes Button emits are all defined", () => {
    const css = readFileSync(join(__dirname, "../../index.css"), "utf-8");

    it.each(["btn", "btn-primary", "btn-danger", "btn-ghost", "btn-sm", "btn-spinner"])(
        ".%s has a rule",
        (name) => {
            expect(css).toMatch(new RegExp(`\\.${name}\\s*[,{]`));
        },
    );

    it("has the keyframes the spinner animates with", () => {
        expect(css).toContain("@keyframes spin");
    });
});
