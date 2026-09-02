import type { ArtifactDetail, VulnSummary } from "~/api/client";
import { StatBand, type StatTile } from "~/components/ui";
import { vulnTile } from "~/components/VulnTile";
import { trustStatus, trustBadgeClass } from "~/utils/trust";
import { relativeDate } from "~/utils/format";

export type ArtifactTab = "versions" | "changelog" | "licenses" | "vulns" | "relationships";

/**
 * The summary band for an artifact: what a reader needs before deciding whether
 * to open a tab.
 *
 * It replaces ArtifactAboutCard, which restated the header's name and type and
 * buried the two facts the header did not carry — signing status and how much of
 * the SBOM set is actually enriched — in a detail grid below the fold. The
 * vulnerability tile is the old bare VulnSummaryBar, folded in.
 *
 * Every tile reads from a query the page already runs eagerly; nothing here adds
 * a request.
 */
export function ArtifactBand(props: {
    artifact: ArtifactDetail;
    isContainer: boolean;
    vulns: VulnSummary | undefined;
    /** The ordering the versions list resolved to, captioning the Versions tile. */
    ordering: "semver" | "all";
    active: ArtifactTab;
    onSelect: (tab: ArtifactTab) => void;
}) {
    const a = () => props.artifact;

    const trust = () => trustStatus(a().signingStatus);

    // How many of this artifact's SBOMs carry enough enrichment to be trusted for
    // provenance and image metadata. The API has reported it since the artifact
    // endpoint was written and no surface has ever shown it, so "5 SBOMs" read as
    // five equally good ones.
    const sbomSub = (): string => {
        const total = a().sbomCount;
        const sufficient = a().sufficientSbomCount;
        if (total === 0) return "none ingested";
        if (sufficient === total) return "all fully enriched";
        return `${sufficient} of ${total} fully enriched`;
    };

    const tiles = (): StatTile<ArtifactTab>[] => {
        const t: StatTile<ArtifactTab>[] = [
            {
                id: "versions",
                head: "Versions",
                value: a().versionCount,
                sub: props.ordering === "semver" ? "semver order" : "by build time",
            },
            {
                head: "SBOMs",
                value: a().sbomCount,
                sub: sbomSub(),
            },
            // The tile passes an id now that the page has a vulnerabilities tab
            // to send the reader to. Without one StatBand renders it as a plain
            // <div> — which is what it was, sitting among buttons doing nothing.
            //
            // The scope is not cosmetic here: this tile counts the newest SBOM
            // of the latest version, while the tab it opens counts across the
            // most recent versions (ocidex-7gf7.5). The two numbers legitimately
            // differ, and without a label the tab looks like it contradicts the
            // tile the reader clicked to reach it.
            vulnTile<ArtifactTab>(props.vulns, "vulns", "latest version"),
        ];

        // Signing is image-only. On an uploaded binary or library it would be a
        // permanent "unsigned" that no amount of enrichment can change, which is
        // why the rest of the page's image chrome is gated the same way.
        if (props.isContainer) {
            t.push({
                // Worst rung across every SBOM, not the latest version's
                // (ocidex-7gf7.3), so it says which — the vulnerability tile
                // beside it is scoped the other way.
                head: (
                    <>
                        Signing
                        <span class="tile-scope">any SBOM</span>
                    </>
                ),
                // trustStatus returns null, not undefined, for an unenriched artifact.
                value: trust()?.label ?? "Not enriched",
                valueClass: (() => {
                    const s = trust();
                    return s !== null ? trustBadgeClass(s.variant) : "text-muted";
                })(),
                // No sub-line. The label already is the whole signal, and the
                // one-line gloss that would distinguish "Verified" from
                // "Signed" is a third phrasing of what utils/trust.ts already
                // owns as `description` — which is how vocabularies drift apart.
            });
        }

        t.push({
            head: "Tracked",
            value: relativeDate(a().createdAt),
            sub: "first seen",
        });

        return t;
    };

    return <StatBand tiles={tiles()} active={props.active} onSelect={props.onSelect} />;
}
