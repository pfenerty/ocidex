// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { render, fireEvent, cleanup } from "@solidjs/testing-library";
import { VersionCell } from "./VersionCell";

// Two different facts used to render as one. Syft writes the literal "UNKNOWN"
// when it resolves a package but not its version — 26 of the first 145
// components of kube-apiserver v1.37.0, all k8s.io staging modules — and
// printing that verbatim in a version column reads as a release someone
// actually named UNKNOWN, sorted in among the real ones.

describe("VersionCell", () => {
    it("prints a real version exactly as it was recorded", () => {
        const { container } = render(() => <VersionCell version="v1.37.0" />);
        expect(container.textContent).toBe("v1.37.0");
        expect(container.querySelector(".font-mono")).not.toBeNull();
    });

    it("says nothing when the SBOM said nothing", () => {
        const absent = render(() => <VersionCell version={undefined} />);
        expect(absent.container.textContent).toBe("—");

        // Empty is absent, not unknown: no claim was made either way.
        const empty = render(() => <VersionCell version="" />);
        expect(empty.container.textContent).toBe("—");
    });

    it("renders the sentinel as a word about the scan, not as a version", () => {
        const { container } = render(() => <VersionCell version="UNKNOWN" />);
        expect(container.textContent).toBe("unknown");
        // Not monospace — monospace is the site's signal for a literal value
        // out of the SBOM, and this is the absence of one.
        expect(container.querySelector(".font-mono")).toBeNull();
    });

    it("matches the sentinel in whatever case it arrives", () => {
        const { container } = render(() => <VersionCell version=" Unknown " />);
        expect(container.textContent).toBe("unknown");
    });

    it("attributes the unknown to the tool that produced the SBOM", () => {
        const { container } = render(() => <VersionCell version="UNKNOWN" />);
        const trigger = container.querySelector(".tooltip-trigger");
        expect(trigger).not.toBeNull();

        fireEvent.mouseEnter(trigger as HTMLElement);
        // The panel is portalled to <body>, so it is not under the container.
        expect(document.querySelector(".tooltip-content")?.textContent).toContain(
            "produced this SBOM",
        );
        cleanup();
    });

    it("leaves a real version unadorned", () => {
        const { container } = render(() => <VersionCell version="1.0.0" />);
        expect(container.querySelector(".tooltip-trigger")).toBeNull();
    });
});
