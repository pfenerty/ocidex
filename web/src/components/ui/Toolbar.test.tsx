// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createSignal } from "solid-js";
import { Router, Route } from "@solidjs/router";
import { render, fireEvent, waitFor, cleanup } from "@solidjs/testing-library";
import { Toolbar, type ToolbarField } from "./Toolbar";

// Real timers with a short debounce, not fake timers: the commit path runs
// through the router's own navigation scheduling, which fake timers desync.
const DEBOUNCE = 20;

// This repo runs vitest without globals, so @solidjs/testing-library cannot
// register its own afterEach — without this, components stay mounted across
// tests and a debounce left pending by one test commits into the next one's URL.
afterEach(cleanup);

const FIELDS: ToolbarField[] = [
    { kind: "text", key: "name", placeholder: "Filter by name…" },
    { kind: "select", key: "type", options: ["library", "container"], allLabel: "All types" },
    { kind: "checkbox", key: "all", label: "Show all" },
];

function renderAt(path: string, fields: ToolbarField[] = FIELDS, onChange?: (v: Record<string, string>) => void) {
    window.history.replaceState({}, "", path);
    return render(() => (
        <Router root={(p) => <>{p.children}</>}>
            <Route
                path="/list"
                component={() => <Toolbar fields={fields} debounceMs={DEBOUNCE} onChange={onChange} />}
            />
        </Router>
    ));
}

const search = () => window.location.search;

/** A missing control should say which one, not throw on a null deref. */
function must<T>(el: T | null | undefined, what: string): T {
    if (el === null || el === undefined) throw new Error(`expected ${what} in the toolbar`);
    return el;
}

const nameInput = (c: HTMLElement) =>
    must(c.querySelector<HTMLInputElement>('input[type="text"]'), "a text input");
const select = (c: HTMLElement) => must(c.querySelector("select"), "a select");
const checkbox = (c: HTMLElement) =>
    must(c.querySelector<HTMLInputElement>('input[type="checkbox"]'), "a checkbox");
const form = (c: HTMLElement) => must(c.querySelector("form"), "the form");
const findClear = (c: HTMLElement) =>
    [...c.querySelectorAll("button")].find((b) => b.textContent.trim() === "Clear");
const clearBtn = (c: HTMLElement) => must(findClear(c), "the Clear button");

describe("Toolbar debounce", () => {
    beforeEach(() => vi.clearAllMocks());

    it("does not commit on the keystroke itself", () => {
        const onChange = vi.fn();
        const { container } = renderAt("/list", FIELDS, onChange);
        fireEvent.input(nameInput(container), { target: { value: "lodash" } });
        // Assert on the commit, not on window.location: router navigation is
        // async, so an undebounced write would also leave the URL briefly empty
        // and this test would pass against a broken implementation.
        expect(onChange).not.toHaveBeenCalled();
        // The box still echoes immediately — the debounce delays the commit,
        // never the displayed value.
        expect(nameInput(container).value).toBe("lodash");
    });

    it("writes the URL once the debounce elapses", async () => {
        const { container } = renderAt("/list");
        fireEvent.input(nameInput(container), { target: { value: "lodash" } });
        await waitFor(() => expect(search()).toBe("?name=lodash"));
    });

    it("coalesces rapid keystrokes into one committed value", async () => {
        const onChange = vi.fn();
        const { container } = renderAt("/list", FIELDS, onChange);
        for (const v of ["l", "lo", "lod"]) {
            fireEvent.input(nameInput(container), { target: { value: v } });
        }
        await waitFor(() => expect(search()).toBe("?name=lod"));
        expect(onChange).toHaveBeenCalledTimes(1);
    });

    it("flushes the pending write on Enter instead of waiting out the timer", async () => {
        const { container } = renderAt("/list");
        fireEvent.input(nameInput(container), { target: { value: "zlib" } });
        fireEvent.submit(form(container));
        // No waitFor delay: the commit is synchronous on submit.
        await waitFor(() => expect(search()).toBe("?name=zlib"));
    });
});

describe("Toolbar URL round-trip", () => {
    it("seeds every field from the URL at mount", () => {
        const { container } = renderAt("/list?name=zlib&type=library&all=1");
        expect(nameInput(container).value).toBe("zlib");
        expect(select(container).value).toBe("library");
        expect(checkbox(container).checked).toBe(true);
    });

    it("commits a select immediately, with no debounce", async () => {
        const { container } = renderAt("/list");
        fireEvent.change(select(container), { target: { value: "container" } });
        await waitFor(() => expect(search()).toBe("?type=container"));
    });

    it("leaves no param behind when a field is set back to All", async () => {
        const { container } = renderAt("/list?type=library");
        fireEvent.change(select(container), { target: { value: "" } });
        // "absent" is the single representation of "not filtering" — never ?type=
        // This asserts the URL contract, not the `undefined` mapping in commit():
        // the router coerces "" to absent as well, so both routes satisfy it. The
        // explicit undefined stays because it states the intent at the call site.
        await waitFor(() => expect(search()).toBe(""));
    });

    it("writes a checkbox as a presence flag", async () => {
        const { container } = renderAt("/list");
        const cb = checkbox(container);
        fireEvent.change(cb, { target: { checked: true } });
        await waitFor(() => expect(search()).toBe("?all=1"));
    });
});

describe("Toolbar clear", () => {
    it("hides the Clear action when nothing is filtered", () => {
        const { container } = renderAt("/list");
        expect(findClear(container)).toBeUndefined();
    });

    it("shows Clear for a draft that has not committed yet", () => {
        const { container } = renderAt("/list");
        fireEvent.input(nameInput(container), { target: { value: "l" } });
        // Otherwise the button is missing while there is visible text in the box,
        // which reads as the button being broken.
        expect(findClear(container)).toBeDefined();
    });

    it("removes every param and empties every input", async () => {
        const { container } = renderAt("/list?name=zlib&type=library&all=1");
        fireEvent.click(clearBtn(container));
        await waitFor(() => expect(search()).toBe(""));
        expect(nameInput(container).value).toBe("");
        expect(select(container).value).toBe("");
        expect(checkbox(container).checked).toBe(false);
    });

    it("cancels a pending debounce so a cleared field does not repopulate", async () => {
        const { container } = renderAt("/list");
        fireEvent.input(nameInput(container), { target: { value: "lodash" } });
        fireEvent.click(clearBtn(container));
        await new Promise((r) => setTimeout(r, DEBOUNCE * 3));
        expect(search()).toBe("");
        expect(nameInput(container).value).toBe("");
    });
});

describe("Toolbar onChange", () => {
    it("reports the full field set, not just the changed key", async () => {
        const onChange = vi.fn();
        const { container } = renderAt("/list?type=library", FIELDS, onChange);
        fireEvent.input(nameInput(container), { target: { value: "zlib" } });
        await waitFor(() => expect(onChange).toHaveBeenCalled());
        expect(onChange.mock.calls[0][0]).toEqual({ name: "zlib", type: "library", all: "" });
    });
});

describe("Toolbar markup contract", () => {
    it("emits .search-bar so it inherits the existing stylesheet", () => {
        const { container } = renderAt("/list");
        expect(form(container).className).toContain("search-bar");
    });

    it("appends a caller class rather than replacing search-bar", () => {
        window.history.replaceState({}, "", "/list");
        const { container } = render(() => (
            <Router root={(p) => <>{p.children}</>}>
                <Route path="/list" component={() => <Toolbar fields={FIELDS} class="mb-4" />} />
            </Router>
        ));
        expect(form(container).className).toBe("search-bar mb-4");
    });

    it("gives every control an accessible name", () => {
        const { container } = renderAt("/list");
        expect(nameInput(container).getAttribute("aria-label")).toBe("Filter by name…");
        expect(select(container).getAttribute("aria-label")).toBe("All types");
    });
});

describe("Toolbar fetched options", () => {
    it("fills a select from a thunk without remounting the row", async () => {
        const [types, setTypes] = createSignal<string[]>([]);
        const fields: ToolbarField[] = [
            { kind: "text", key: "name", placeholder: "Filter by name…" },
            { kind: "select", key: "type", options: () => types(), allLabel: "All types" },
        ];
        const { container } = renderAt("/list", fields);
        expect([...select(container).options].map((o) => o.value)).toEqual([""]);

        // A caller whose choices come from a query must not have to rebuild the
        // `fields` array to show them: that array is what the toolbar renders
        // one row per, so a new identity would remount the text input beside
        // the select and take the half-typed word with it.
        const input = nameInput(container);
        fireEvent.input(input, { target: { value: "half-typed" } });
        setTypes(["npm", "golang"]);

        expect([...select(container).options].map((o) => o.value)).toEqual(["", "npm", "golang"]);
        expect(nameInput(container)).toBe(input);
        expect(input.value).toBe("half-typed");

        await waitFor(() => {
            expect(search()).toBe("?name=half-typed");
        });
    });

    it("still seeds a fetched select from the URL when the options arrive late", () => {
        const [types, setTypes] = createSignal<string[]>([]);
        const fields: ToolbarField[] = [
            { kind: "select", key: "type", options: () => types(), allLabel: "All types" },
        ];
        const { container } = renderAt("/list?type=npm", fields);
        // Nothing to select yet, so the browser holds "All".
        expect(select(container).value).toBe("");

        setTypes(["npm", "golang"]);

        // Without re-asserting on the option list, the value binding never runs
        // again and the row reads "All types" over an npm-filtered list.
        expect(select(container).value).toBe("npm");
    });
});
