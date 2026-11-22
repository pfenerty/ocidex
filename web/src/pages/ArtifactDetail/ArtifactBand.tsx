import type { ArtifactDetail, CountedSBOM, VulnSummary } from "~/api/client";
import { countedLabel } from "~/utils/vuln";
import type { CriticalChange } from "~/utils/versionDelta";
import { StatBand, type StatTile } from "~/components/ui";
import { vulnTile } from "~/components/VulnTile";
import { relativeDate } from "~/utils/format";

export type ArtifactTab = "versions" | "changelog" | "licenses" | "vulns" | "relationships" | "running";

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
    vulns: VulnSummary | undefined;
    /** The version the vulnerability summary counts, named in the tile's scope:
     *  the highest by version parts, which need not be the newest build. */
    vulnsVersion?: string;
    /** The SBOM the summary counts; names version and architecture in the scope. */
    vulnsCounted?: CountedSBOM;
    /** How that version's critical count changed from the one before it. */
    vulnsChange?: CriticalChange;
    /** That version's SBOM has been matched against the vulnerability store. */
    vulnsMatched?: boolean;
    /** The ordering the versions list resolved to, captioning the Versions tile. */
    ordering: "semver" | "all";
    active: ArtifactTab;
    onSelect: (tab: ArtifactTab) => void;
}) {
    const a = () => props.artifact;


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
                sub: props.ordering === "semver" ? "semver order" : "all versions",
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
            vulnTile<ArtifactTab>(
                props.vulns,
                "vulns",
                countedLabel(props.vulnsCounted) ??
                    (props.vulnsVersion !== undefined && props.vulnsVersion !== ""
                        ? props.vulnsVersion
                        : "latest version"),
                props.vulnsMatched,
                props.vulnsChange,
            ),
        ];

        t.push({
            head: "Tracked",
            value: relativeDate(a().createdAt),
            sub: "first seen",
        });

        return t;
    };

    return <StatBand tiles={tiles()} active={props.active} onSelect={props.onSelect} />;
}
