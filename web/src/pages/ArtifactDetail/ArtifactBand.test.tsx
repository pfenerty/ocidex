// @vitest-environment happy-dom
import { describe, it, expect, vi, afterEach } from "vitest";
import { render, fireEvent, cleanup } from "@solidjs/testing-library";
import type { ArtifactDetail, VulnSummary } from "~/api/client";
import { ArtifactBand } from "./ArtifactBand";

afterEach(cleanup);

const ARTIFACT: ArtifactDetail = {
    id: "a1",
    type: "container",
    name: "ghcr.io/dexidp/dex",
    sbomCount: 5,
    sufficientSbomCount: 5,
    signingStatus: "signed",
    createdAt: "2026-07-14T12:00:50Z",
    versionCount: 60,
    watched: false,
};

const VULNS: VulnSummary = { total: 85, critical: 12, high: 30, medium: 40, low: 3, unknown: 0 };

type BandProps = Parameters<typeof ArtifactBand>[0];

// Merged in plain JS, then spread once. Solid's mergeProps skips an `undefined`
// value in a later source so that defaults survive, which would silently ignore
// the `vulns: undefined` case this file needs to cover.
function renderBand(over: Partial<BandProps> = {}) {
    const props: BandProps = {
        artifact: ARTIFACT,
        isContainer: true,
        vulns: VULNS,
        ordering: "semver",
        active: "versions",
        onSelect: () => undefined,
        ...over,
    };
    return render(() => <ArtifactBand {...props} />);
}

/**
 * A tile's label with its scope stripped off. The head carries both since
 * ocidex-7gf7.7, and matching on the raw textContent would tie every lookup
 * below to the wording of a caption none of them is about.
 */
function headLabel(t: HTMLElement): string {
    const head = t.querySelector(".tile-head");
    if (head === null) return "";
    const copy = head.cloneNode(true) as HTMLElement;
    copy.querySelector(".tile-scope")?.remove();
    return copy.textContent.trim();
}

function tileScope(t: HTMLElement): string {
    return t.querySelector(".tile-scope")?.textContent.trim() ?? "";
}

function tile(container: HTMLElement, head: string): HTMLElement {
    const found = [...container.querySelectorAll<HTMLElement>(".tile")].find(
        (t) => headLabel(t) === head,
    );
    if (found === undefined) throw new Error(`no "${head}" tile in the band`);
    return found;
}

function sub(container: HTMLElement, head: string): string {
    return tile(container, head).querySelector(".tile-sub")?.textContent.trim() ?? "";
}

describe("ArtifactBand signing tile", () => {
    it("shows signing for a container", () => {
        const { container } = renderBand();
        expect(tile(container, "Signing").textContent).toContain("Signed");
    });

    it("omits signing entirely for a non-container", () => {
        // On an uploaded binary this would be a permanent "unsigned" that no
        // amount of enrichment can change, so it is absent rather than bad news.
        const { container } = renderBand({ isContainer: false });
        expect(() => tile(container, "Signing")).toThrow();
    });

    it("says not enriched rather than unsigned when the status is unknown", () => {
        const { container } = renderBand({ artifact: { ...ARTIFACT, signingStatus: "" } });
        expect(tile(container, "Signing").textContent).toContain("Not enriched");
    });
});

describe("ArtifactBand SBOM coverage", () => {
    // sufficientSbomCount has been in the API since the artifact endpoint was
    // written and no surface ever showed it, so "5 SBOMs" read as five equally
    // good ones.
    it("says so when every SBOM is fully enriched", () => {
        const { container } = renderBand();
        expect(sub(container, "SBOMs")).toBe("all fully enriched");
    });

    it("quotes the shortfall when only some are", () => {
        const { container } = renderBand({ artifact: { ...ARTIFACT, sufficientSbomCount: 3 } });
        expect(sub(container, "SBOMs")).toBe("3 of 5 fully enriched");
    });

    it("does not claim coverage over an empty SBOM set", () => {
        const { container } = renderBand({
            artifact: { ...ARTIFACT, sbomCount: 0, sufficientSbomCount: 0 },
        });
        expect(sub(container, "SBOMs")).toBe("none ingested");
    });
});

describe("ArtifactBand vulnerability tile", () => {
    it("captions the count with the worst severity present", () => {
        const { container } = renderBand();
        expect(sub(container, "Vulnerabilities")).toBe("12 critical");
    });

    it("says not scanned rather than zero when there is no summary", () => {
        // ADR-044's rule, applied here: unknown must never read as clean.
        const { container } = renderBand({ vulns: undefined });
        const t = tile(container, "Vulnerabilities");
        expect(t.querySelector(".tile-value")?.textContent).toBe("—");
        expect(sub(container, "Vulnerabilities")).toBe("not scanned");
    });

    it("is a button, because the page now has a vulnerabilities tab", () => {
        // The inverse of what this asserted before ocidex-unn8.6, and still the
        // same property: the tag must match whether there is anywhere to go. A
        // DIV here means the destination went missing and the tile silently
        // became decoration again.
        const { container } = renderBand();
        expect(tile(container, "Vulnerabilities").tagName).toBe("BUTTON");
    });
});

describe("ArtifactBand tile scopes", () => {
    // The two count tiles are scoped opposite ways and sit side by side, and
    // the vulnerability tile opens a tab whose own count spans more versions
    // than the tile does (ocidex-7gf7.5). Without the labels the tab reads as
    // contradicting the tile the reader clicked to reach it.
    it("scopes the vulnerability tile to the latest version", () => {
        const { container } = renderBand();
        expect(tileScope(tile(container, "Vulnerabilities"))).toBe("latest version");
    });

    it("scopes the signing tile to any SBOM", () => {
        const { container } = renderBand();
        expect(tileScope(tile(container, "Signing"))).toBe("any SBOM");
    });
});

describe("ArtifactBand navigation", () => {
    it("reports the tab id when a selectable tile is clicked", () => {
        const onSelect = vi.fn();
        const { container } = renderBand({ onSelect });
        fireEvent.click(tile(container, "Versions"));
        expect(onSelect).toHaveBeenCalledWith("versions");
    });

    it("captions the versions tile with the ordering in effect", () => {
        // The semver/all control moved out of a second tab strip, so the band is
        // now the only thing on screen saying which ordering the list is in.
        expect(sub(renderBand().container, "Versions")).toBe("semver order");
        cleanup();
        expect(sub(renderBand({ ordering: "all" }).container, "Versions")).toBe("by build time");
    });
});
