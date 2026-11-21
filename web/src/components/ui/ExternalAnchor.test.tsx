// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { render } from "@solidjs/testing-library";
import { ExternalAnchor } from "./ExternalAnchor";
import { LinkedField } from "~/components/metadata/LinkedField";
import { GitCommitCell } from "~/components/cells/GitCommitCell";

// A call, so solid/jsx-no-script-url does not flag the test input itself.
const scriptUrl = (): string => ["javascript", "alert(1)"].join(":");

describe("ExternalAnchor", () => {
    it("links an https URL in a new tab", () => {
        const { container } = render(() => <ExternalAnchor url="https://example.com/x">x</ExternalAnchor>);
        const a = container.querySelector("a");
        expect(a?.getAttribute("href")).toBe("https://example.com/x");
        expect(a?.getAttribute("target")).toBe("_blank");
        expect(a?.getAttribute("rel")).toBe("noopener noreferrer");
    });

    it("renders a javascript: URL as text, with no href", () => {
        const { container } = render(() => <ExternalAnchor url={scriptUrl()}>click</ExternalAnchor>);
        expect(container.querySelector("a")).toBeNull();
        expect(container.querySelector("[href]")).toBeNull();
        expect(container.textContent).toBe("click");
    });
});

describe("components fed attacker-controlled URLs", () => {
    it("LinkedField renders no href for javascript:", () => {
        const { container } = render(() => <LinkedField label="Source" url={scriptUrl()} />);
        expect(container.querySelector("[href]")).toBeNull();
    });

    it("GitCommitCell renders no href for javascript:", () => {
        const { container } = render(() => <GitCommitCell sha="0123456789abcdef" url={scriptUrl()} />);
        expect(container.querySelector("[href]")).toBeNull();
        expect(container.textContent).toContain("0123456789ab");
    });
});
