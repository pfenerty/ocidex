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
        const selects = container.querySelectorAll("select");
        // Order in markup: from-artifact, from-sbom, to-artifact, to-sbom
        const fromArtifact = selects[0];
        const fromSbom = selects[1];
        const toArtifact = selects[2];
        const toSbom = selects[3];

        // Pick the same artifact on both sides so the SBOM dropdowns populate.
        fireEvent.change(fromArtifact, { target: { value: "art-multi" } });
        fireEvent.change(toArtifact, { target: { value: "art-multi" } });

        // Pick an aarch64 SBOM on the from side.
        fireEvent.change(fromSbom, { target: { value: "sbom-aarch64-a" } });

        // To-side options: placeholder + aarch64-a + aarch64-b. s390x and amd64 hidden.
        const toValues = Array.from(toSbom.options).map((o) => o.value);
        expect(toValues).toContain("sbom-aarch64-a");
        expect(toValues).toContain("sbom-aarch64-b");
        expect(toValues).not.toContain("sbom-s390x");
        expect(toValues).not.toContain("sbom-amd64");
    });

    it("shows all archs after 'show all architectures' toggle is enabled", () => {
        const { container, getByLabelText } = render(() => <Diff />);
        const selects = container.querySelectorAll("select");
        const fromArtifact = selects[0];
        const fromSbom = selects[1];
        const toArtifact = selects[2];
        const toSbom = selects[3];

        fireEvent.change(fromArtifact, { target: { value: "art-multi" } });
        fireEvent.change(toArtifact, { target: { value: "art-multi" } });
        fireEvent.change(fromSbom, { target: { value: "sbom-aarch64-a" } });

        // Toggle is now visible because from has an arch. Click it.
        const toggle = getByLabelText(/show all architectures/i);
        fireEvent.click(toggle);

        const toValues = Array.from(toSbom.options).map((o) => o.value);
        expect(toValues).toContain("sbom-aarch64-a");
        expect(toValues).toContain("sbom-s390x");
        expect(toValues).toContain("sbom-amd64");
    });

    it("does not filter when From has no architecture", () => {
        // Override default: from-side SBOM has no arch.
        mockUseArtifactSBOMs.mockImplementation(() => ({
            isLoading: false,
            isError: false,
            data: {
                data: [
                    { id: "sbom-noarch", createdAt: "2026-05-01T00:00:00Z", subjectVersion: "1.0", artifactId: "art-multi", specVersion: "1.6", sufficient: true, version: 1 },
                    makeSBOM("sbom-s390x", "s390x", "1.0"),
                    makeSBOM("sbom-amd64", "amd64", "1.0"),
                ],
            },
        }));
        const { container } = render(() => <Diff />);
        const selects = container.querySelectorAll("select");
        const fromArtifact = selects[0];
        const fromSbom = selects[1];
        const toArtifact = selects[2];
        const toSbom = selects[3];

        fireEvent.change(fromArtifact, { target: { value: "art-multi" } });
        fireEvent.change(toArtifact, { target: { value: "art-multi" } });
        fireEvent.change(fromSbom, { target: { value: "sbom-noarch" } });

        const toValues = Array.from(toSbom.options).map((o) => o.value);
        // All SBOMs visible because from has no arch to couple on.
        expect(toValues).toContain("sbom-s390x");
        expect(toValues).toContain("sbom-amd64");
    });
});
