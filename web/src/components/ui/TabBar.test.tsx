// @vitest-environment happy-dom
import { describe, it, expect, vi } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import { TabBar } from "./TabBar";

const tabs = [
    { id: "versions", label: "Versions" },
    { id: "changelog", label: "Changelog", title: "What changed" },
] as const;

describe("TabBar", () => {
    it("marks exactly the active tab", () => {
        const { container } = render(() => (
            <TabBar tabs={tabs} active="changelog" onSelect={() => undefined} />
        ));
        const active = container.querySelectorAll("button.active");
        expect(active.length).toBe(1);
        expect(active[0].textContent).toBe("Changelog");
    });

    it("reports the selected id", () => {
        const onSelect = vi.fn();
        const { getByText } = render(() => (
            <TabBar tabs={tabs} active="versions" onSelect={onSelect} />
        ));
        fireEvent.click(getByText("Changelog"));
        expect(onSelect).toHaveBeenCalledWith("changelog");
    });

    // The hand-written form of this was one ternary per tab, so the highlight
    // could lag the state if a copy-pasted ternary kept the wrong id. Driving
    // it from a signal proves the class actually tracks `active`.
    it("moves the highlight when active changes", () => {
        const [active, setActive] = createSignal<"versions" | "changelog">("versions");
        const { container } = render(() => (
            <TabBar tabs={tabs} active={active()} onSelect={setActive} />
        ));
        expect(container.querySelector("button.active")?.textContent).toBe("Versions");
        setActive("changelog");
        expect(container.querySelector("button.active")?.textContent).toBe("Changelog");
    });

    it("passes titles through for hover help", () => {
        const { getByText } = render(() => (
            <TabBar tabs={tabs} active="versions" onSelect={() => undefined} />
        ));
        expect(getByText("Changelog").getAttribute("title")).toBe("What changed");
    });
});
