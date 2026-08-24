// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { render } from "@solidjs/testing-library";
import { PageHeader } from "./PageHeader";

describe("PageHeader structure", () => {
    it("emits the class structure Layout.css styles", () => {
        const { container } = render(() => <PageHeader title="Artifacts" />);
        const header = container.querySelector(".page-header");
        expect(header).toBeTruthy();
        expect(header?.querySelector(".page-header-row h2")?.textContent).toBe("Artifacts");
    });

    // `.page-header-row` is justify-content: space-between. If the title, the
    // subtitle and the actions are emitted as three siblings they spread across
    // the row and the actions stop being right-aligned — so the title block has
    // to stay wrapped as a single child.
    it("keeps the row to exactly two children: the title block and the actions", () => {
        const { container } = render(() => (
            <PageHeader title="Clusters" subtitle="What your clusters run" actions={<button>Add</button>} />
        ));
        const row = container.querySelector(".page-header-row");
        expect(row?.children.length).toBe(2);
        expect(row?.children[0].querySelector("h2")?.textContent).toBe("Clusters");
        expect(row?.children[0].querySelector("p")?.textContent).toBe("What your clusters run");
        expect(row?.children[1].textContent).toBe("Add");
    });

    it("puts actions after the title block, so they land in the right-hand slot", () => {
        const { container } = render(() => (
            <PageHeader title="T" actions={<span class="probe">A</span>} />
        ));
        const row = container.querySelector(".page-header-row");
        const actions = container.querySelector(".probe");
        expect(row?.lastElementChild?.contains(actions ?? null)).toBe(true);
    });
});

describe("PageHeader optional slots", () => {
    it("renders no <p> when there is no subtitle", () => {
        const { container } = render(() => <PageHeader title="Artifacts" />);
        expect(container.querySelector(".page-header p")).toBeNull();
    });

    it("leaves the row with one child when there are no actions", () => {
        const { container } = render(() => <PageHeader title="Artifacts" subtitle="s" />);
        expect(container.querySelector(".page-header-row")?.children.length).toBe(1);
    });

    it("renders no breadcrumb container unless given one", () => {
        const { container } = render(() => <PageHeader title="Artifacts" />);
        expect(container.querySelector(".breadcrumb")).toBeNull();
    });

    it("renders the breadcrumb above the title", () => {
        const { container } = render(() => (
            <PageHeader breadcrumb={<a href="/components">Components</a>} title="lodash" />
        ));
        const header = container.querySelector(".page-header");
        expect(header?.firstElementChild?.className).toBe("breadcrumb");
        expect(header?.querySelector(".breadcrumb a")?.textContent).toBe("Components");
    });
});

describe("PageHeader content", () => {
    // Detail pages put markup in the title — a registry link, a mono version
    // span — so the title cannot be typed as a string.
    it("accepts elements, not just text, for title and subtitle", () => {
        const { container } = render(() => (
            <PageHeader
                title={<a href="/x">github.com/pfenerty/ocidex</a>}
                subtitle={<span class="badge">application</span>}
            />
        ));
        expect(container.querySelector("h2 a")?.getAttribute("href")).toBe("/x");
        expect(container.querySelector("p .badge")?.textContent).toBe("application");
    });

    // `.page-header p` already resolves to --color-text-muted, so the
    // `text-muted` class several call sites add is a no-op. The primitive does
    // not carry it forward.
    it("does not decorate the subtitle with a redundant class", () => {
        const { container } = render(() => <PageHeader title="T" subtitle="s" />);
        expect(container.querySelector(".page-header p")?.className).toBe("");
    });
});
