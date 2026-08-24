// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
import Diff from "./Diff";
import type { SBOMSummary } from "~/api/client";

const mockSetSearchParams = vi.fn();
let mockSearchParams: { from?: string; to?: string } = {};
vi.mock("@solidjs/router", () => ({
    useSearchParams: () => [mockSearchParams, mockSetSearchParams],
}));

const artifacts = [
    { id: "art-multi", name: "ghcr.io/example/svc", type: "container", sbomCount: 5, sufficientSbomCount: 5 },
];

interface QueryStub<T> {
    isLoading: boolean;
    isError: boolean;
    data?: { data: T[] };
}

const mockUseArtifacts = vi.fn<() => QueryStub<typeof artifacts[number]>>();
const mockUseArtifactSBOMs = vi.fn<(id: string) => QueryStub<SBOMSummary>>();
vi.mock("~/api/queries", () => ({
    useArtifacts: () => mockUseArtifacts(),
    useArtifactSBOMs: (id: () => string) => mockUseArtifactSBOMs(id()),
}));

vi.mock("~/components/DiffPairView", () => ({
    DiffPairView: () => null,
    ViewToggle: () => null,
}));

function makeSBOM(id: string, arch: string, version: string): SBOMSummary {
    return {
        id,
        createdAt: "2026-05-01T00:00:00Z",
        architecture: arch,
        subjectVersion: version,
        artifactId: "art-multi",
        specVersion: "1.6",
        sufficient: true,
        version: 1,
    };
}

/**
 * The picker is four comboboxes now, not four `<select>`s (ocidex-ag4q.41), so
 * "what are my options" is "open the list and read it" rather than reading
 * `select.options`. These helpers keep the assertions about *choices offered*
 * rather than about the markup that offers them.
 */
function box(container: HTMLElement, label: string): HTMLInputElement {
    const el = container.querySelector<HTMLInputElement>(`input[aria-label="${label}"]`);
    if (el === null) throw new Error(`no combobox labelled ${label}`);
    return el;
}

/** Open `label`'s list and return the option labels it offers. */
function optionsOf(container: HTMLElement, label: string): string[] {
    fireEvent.focus(box(container, label));
    return Array.from(container.querySelectorAll('[role="option"]')).map(
        (li) => li.textContent,
    );
}

/** Type enough to isolate one option, then pick it. */
function pick(container: HTMLElement, label: string, query: string): void {
    const input = box(container, label);
    fireEvent.focus(input);
    fireEvent.input(input, { target: { value: query } });
    const first = container.querySelector('[role="option"]');
    if (first === null) throw new Error(`no option matching ${query} under ${label}`);
    fireEvent.mouseDown(first);
}

describe("Diff page picker — arch coupling", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockSearchParams = {};
        mockUseArtifacts.mockReturnValue({ isLoading: false, isError: false, data: { data: artifacts } });
        mockUseArtifactSBOMs.mockImplementation((_id: string) => ({
            isLoading: false,
            isError: false,
            data: {
                data: [
                    makeSBOM("sbom-aarch64-a", "aarch64", "1.0"),
                    makeSBOM("sbom-aarch64-b", "aarch64", "1.1"),
                    makeSBOM("sbom-s390x", "s390x", "1.0"),
                    makeSBOM("sbom-amd64", "amd64", "1.0"),
                ],
            },
        }));
    });

    it("filters 'To' SBOMs to match 'From' arch by default once From is selected", () => {
        const { container } = render(() => <Diff />);

        // Pick the same artifact on both sides so the SBOM pickers populate.
        pick(container, "From artifact", "svc");
        pick(container, "To artifact", "svc");

        // Pick an aarch64 SBOM on the from side.
        pick(container, "From SBOM", "1.0 aarch64");

        const toOptions = optionsOf(container, "To SBOM").join("|");
        expect(toOptions).toContain("aarch64");
        expect(toOptions).not.toContain("s390x");
        expect(toOptions).not.toContain("amd64");
    });

    it("shows all archs after 'show all architectures' toggle is enabled", () => {
        const { container, getByLabelText } = render(() => <Diff />);

        pick(container, "From artifact", "svc");
        pick(container, "To artifact", "svc");
        pick(container, "From SBOM", "1.0 aarch64");

        // Toggle is now visible because from has an arch. Click it.
        fireEvent.click(getByLabelText(/show all architectures/i));

        const toOptions = optionsOf(container, "To SBOM").join("|");
        expect(toOptions).toContain("aarch64");
        expect(toOptions).toContain("s390x");
        expect(toOptions).toContain("amd64");
    });

    it("does not filter when From has no architecture", () => {
        // Override default: from-side SBOM has no arch.
        mockUseArtifactSBOMs.mockImplementation(() => ({
            isLoading: false,
            isError: false,
            data: {
                data: [
                    { id: "sbom-noarch", createdAt: "2026-05-01T00:00:00Z", subjectVersion: "9.9", artifactId: "art-multi", specVersion: "1.6", sufficient: true, version: 1 },
                    makeSBOM("sbom-s390x", "s390x", "1.0"),
                    makeSBOM("sbom-amd64", "amd64", "1.0"),
                ],
            },
        }));
        const { container } = render(() => <Diff />);

        pick(container, "From artifact", "svc");
        pick(container, "To artifact", "svc");
        pick(container, "From SBOM", "9.9");

        const toOptions = optionsOf(container, "To SBOM").join("|");
        // All SBOMs visible because from has no arch to couple on.
        expect(toOptions).toContain("s390x");
        expect(toOptions).toContain("amd64");
    });

    it("narrows the SBOM list as you type instead of making you scroll it", () => {
        const { container } = render(() => <Diff />);
        pick(container, "From artifact", "svc");

        expect(optionsOf(container, "From SBOM")).toHaveLength(4);

        const input = box(container, "From SBOM");
        fireEvent.input(input, { target: { value: "s390x" } });
        expect(container.querySelectorAll('[role="option"]')).toHaveLength(1);
    });

    it("keeps the SBOM picker disabled until an artifact is chosen", () => {
        const { container } = render(() => <Diff />);
        expect(box(container, "From SBOM").disabled).toBe(true);
        pick(container, "From artifact", "svc");
        expect(box(container, "From SBOM").disabled).toBe(false);
    });
});
