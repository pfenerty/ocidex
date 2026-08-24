// @vitest-environment happy-dom
import { describe, it, expect, vi } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import { Combobox } from "./Combobox";

interface Item {
    id: string;
    name: string;
    sub: string;
}

const items: Item[] = [
    { id: "a", name: "alpine", sub: "container" },
    { id: "b", name: "busybox", sub: "container" },
    { id: "c", name: "curl", sub: "library" },
];

function mount(onSelect: (id: string) => void = vi.fn(), value = "") {
    const [v, setV] = createSignal(value);
    const result = render(() => (
        <Combobox
            label="Image"
            placeholder="Search..."
            items={items}
            value={v()}
            onSelect={(id) => {
                setV(id);
                onSelect(id);
            }}
            itemId={(i) => i.id}
            itemLabel={(i) => i.name}
            itemSub={(i) => i.sub}
        />
    ));
    const input = result.container.querySelector<HTMLInputElement>('input[role="combobox"]');
    if (input === null) throw new Error("no combobox rendered");
    const options = () => Array.from(result.container.querySelectorAll('[role="option"]'));
    return { ...result, input, options };
}

describe("Combobox", () => {
    it("stays closed until focused, then offers every item", () => {
        const { input, options } = mount();
        expect(options()).toHaveLength(0);
        expect(input.getAttribute("aria-expanded")).toBe("false");

        fireEvent.focus(input);
        expect(options()).toHaveLength(3);
        expect(input.getAttribute("aria-expanded")).toBe("true");
    });

    it("filters on every whitespace-separated term, across label and sub", () => {
        const { input, options } = mount();
        fireEvent.focus(input);

        fireEvent.input(input, { target: { value: "busy" } });
        expect(options().map((o) => o.textContent)).toEqual(["busyboxcontainer"]);

        // Terms may match different fields, in either order.
        fireEvent.input(input, { target: { value: "library curl" } });
        expect(options()).toHaveLength(1);

        fireEvent.input(input, { target: { value: "ALPINE" } });
        expect(options()).toHaveLength(1);
    });

    it("reports the empty message rather than an empty box", () => {
        const { input, options, getByText } = mount();
        fireEvent.focus(input);
        fireEvent.input(input, { target: { value: "nothing-matches" } });
        expect(options()).toHaveLength(0);
        expect(getByText("No matches")).toBeTruthy();
    });

    it("selects with mousedown and shows the selection at rest", () => {
        const onSelect = vi.fn();
        const { input, options } = mount(onSelect);
        fireEvent.focus(input);
        fireEvent.input(input, { target: { value: "curl" } });
        fireEvent.mouseDown(options()[0]);

        expect(onSelect).toHaveBeenCalledWith("c");
        expect(options()).toHaveLength(0);
        expect(input.value).toBe("curl");
    });

    it("navigates with the arrow keys and commits with Enter", () => {
        const onSelect = vi.fn();
        const { input } = mount(onSelect);
        fireEvent.focus(input);
        fireEvent.keyDown(input, { key: "ArrowDown" }); // a -> b
        fireEvent.keyDown(input, { key: "Enter" });
        expect(onSelect).toHaveBeenCalledWith("b");
    });

    it("wraps the highlight rather than sticking at the ends", () => {
        const onSelect = vi.fn();
        const { input } = mount(onSelect);
        fireEvent.focus(input);
        fireEvent.keyDown(input, { key: "ArrowUp" }); // wraps to the last
        fireEvent.keyDown(input, { key: "Enter" });
        expect(onSelect).toHaveBeenCalledWith("c");
    });

    it("Escape closes without disturbing the selection", () => {
        const onSelect = vi.fn();
        const { input, options } = mount(onSelect, "a");
        fireEvent.focus(input);
        fireEvent.input(input, { target: { value: "curl" } });
        fireEvent.keyDown(input, { key: "Escape" });

        expect(options()).toHaveLength(0);
        expect(onSelect).not.toHaveBeenCalled();
        expect(input.value).toBe("alpine");
    });

    it("offers a clear button only once something is selected", () => {
        const onSelect = vi.fn();
        const { queryByLabelText } = mount(onSelect, "");
        expect(queryByLabelText("Clear Image")).toBeNull();

        const picked = mount(onSelect, "a");
        fireEvent.click(picked.getByLabelText("Clear Image"));
        expect(onSelect).toHaveBeenCalledWith("");
    });

    it("does not open when disabled", () => {
        const { container } = render(() => (
            <Combobox
                label="Image"
                items={items}
                value=""
                onSelect={vi.fn()}
                itemId={(i) => i.id}
                itemLabel={(i) => i.name}
                disabled
            />
        ));
        const input = container.querySelector<HTMLInputElement>('input[role="combobox"]');
        expect(input?.disabled).toBe(true);
        expect(container.querySelectorAll('[role="option"]')).toHaveLength(0);
    });
});
