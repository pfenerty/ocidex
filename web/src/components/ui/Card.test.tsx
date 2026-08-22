// @vitest-environment happy-dom
import { describe, it, expect, vi } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
import { Card, CardHeader } from "./Card";
import { DetailGrid, DetailField } from "./DetailGrid";
import { FormField, CheckboxField } from "./FormField";
import { Modal } from "./Modal";
import { createExpandedSet } from "./expanded";
import { createRoot } from "solid-js";

describe("Card", () => {
    it("keeps the card > card-header nesting the CSS targets", () => {
        const { container } = render(() => (
            <Card>
                <CardHeader title="Artifacts" count={3} />
            </Card>
        ));
        expect(container.querySelector(".card > .card-header h3")?.textContent).toBe("Artifacts");
        expect(container.querySelector(".card-header .badge")?.textContent).toBe("3");
    });

    // `.card-header` is space-between. If the title, the badge and the actions
    // are three bare children, the badge lands in the middle of the row and
    // reads as a stray number; it belongs beside the heading it counts.
    it("groups the count with the title so only actions sit on the right", () => {
        const { container } = render(() => (
            <CardHeader title="Artifacts" count={3} actions={<button>See all</button>} />
        ));
        const header = container.querySelector(".card-header");
        if (header === null) throw new Error("no card-header rendered");
        expect(header.children.length).toBe(2);
        expect(header.children[0].className).toBe("card-header-title");
        expect(header.children[0].querySelector("h3")?.textContent).toBe("Artifacts");
        expect(header.children[0].querySelector(".badge")?.textContent).toBe("3");
        expect(header.children[1].textContent).toBe("See all");
    });

    it("omits the count badge when no count is given", () => {
        const { container } = render(() => <CardHeader title="Artifacts" />);
        expect(container.querySelector(".badge")).toBeNull();
    });

    it("appends extra classes rather than replacing `card`", () => {
        const { container } = render(() => <Card class="mb-4">body</Card>);
        expect(container.querySelector(".card")?.className).toBe("card mb-4");
    });
});

describe("DetailField", () => {
    it("renders label and value in the classes DetailSection.css styles", () => {
        const { container } = render(() => (
            <DetailGrid>
                <DetailField label="Name">nginx</DetailField>
            </DetailGrid>
        ));
        expect(container.querySelector(".detail-grid .detail-field .detail-label")?.textContent).toBe("Name");
        expect(container.querySelector(".detail-value")?.textContent).toBe("nginx");
    });

    // `when` replaces an explicit <Show> at each call site; a falsy value must
    // drop the whole field, not render an empty label with a blank value.
    it("drops the entire field when `when` is falsy", () => {
        const { container } = render(() => (
            <DetailField label="Group" when={undefined as string | undefined}>
                —
            </DetailField>
        ));
        expect(container.querySelector(".detail-field")).toBeNull();
    });

    it("renders the field when `when` is satisfied", () => {
        const { container } = render(() => (
            <DetailField label="Group" when="io.example">
                io.example
            </DetailField>
        ));
        expect(container.querySelector(".detail-value")?.textContent).toBe("io.example");
    });
});

describe("FormField", () => {
    it("renders the hint next to the label", () => {
        const { container } = render(() => (
            <FormField label="Auth Token" hint="(optional)">
                <input />
            </FormField>
        ));
        expect(container.querySelector("label")?.textContent).toContain("(optional)");
        expect(container.querySelector("input")).not.toBeNull();
    });

    it("reports checkbox changes as booleans", () => {
        const onChange = vi.fn();
        const { container } = render(() => (
            <CheckboxField label="Enabled" checked={false} onChange={onChange} />
        ));
        const box = container.querySelector("input");
        if (box === null) throw new Error("no checkbox rendered");
        fireEvent.click(box);
        expect(onChange).toHaveBeenCalledWith(true);
    });

    it("does not fire onChange while disabled", () => {
        const onChange = vi.fn();
        const { container } = render(() => (
            <CheckboxField label="Include untagged" checked={false} disabled onChange={onChange} />
        ));
        const box = container.querySelector("input");
        if (box === null) throw new Error("no checkbox rendered");
        fireEvent.click(box);
        expect(onChange).not.toHaveBeenCalled();
    });
});

describe("Modal", () => {
    it("hands the dialog element back to the caller for showModal()", () => {
        let el: HTMLDialogElement | undefined;
        const { container } = render(() => (
            <Modal ref={(e) => (el = e)} title="Add Registry">
                <p>body</p>
            </Modal>
        ));
        expect(el).toBe(container.querySelector("dialog"));
        expect(container.querySelector("dialog .card-header h3")?.textContent).toBe("Add Registry");
    });

    it("invokes onClose for the native close event, which Escape also raises", () => {
        const onClose = vi.fn();
        const { container } = render(() => (
            <Modal ref={() => undefined} title="Edit" onClose={onClose}>
                <p>body</p>
            </Modal>
        ));
        const dialog = container.querySelector("dialog");
        if (dialog === null) throw new Error("no dialog rendered");
        fireEvent(dialog, new Event("close"));
        expect(onClose).toHaveBeenCalled();
    });
});

describe("createExpandedSet", () => {
    it("toggles keys independently and clears", () => {
        createRoot((dispose) => {
            const set = createExpandedSet();
            expect(set.has("a")).toBe(false);
            set.toggle("a");
            set.toggle("b");
            expect(set.has("a")).toBe(true);
            expect(set.has("b")).toBe(true);
            set.toggle("a");
            expect(set.has("a")).toBe(false);
            expect(set.has("b")).toBe(true);
            set.replace(new Set(["c"]));
            expect(set.has("b")).toBe(false);
            expect(set.has("c")).toBe(true);
            set.clear();
            expect(set.has("c")).toBe(false);
            dispose();
        });
    });
});
