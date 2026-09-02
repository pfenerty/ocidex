import type { ComponentDetail, VulnSummary } from "~/api/client";
import { StatBand, type StatTile } from "~/components/ui";
import { vulnTile } from "~/components/VulnTile";
import type { ComponentTab } from "~/components/ComponentMetadata";
import { plural, hasText } from "~/utils/format";

/**
 * Where the corpus-wide half of the band comes from: /components/versions
 * reports these for the whole result set, not the page (ocidex-ag4q.35).
 */
export interface CorpusCounts {
    /** Distinct artifacts whose SBOMs contain this component. */
    artifactCount: number;
    /** Distinct versions of this component across the corpus. */
    versionCount: number;
    /** SBOM occurrences — the pagination total. */
    sbomCount: number;
}

/**
 * The summary band for one component instance.
 *
 * A reader arriving here from a licence list or a diff tree has four questions,
 * and the page answered none of them above the fold: where is this used, how
 * many versions of it are we carrying, what is it licensed under, and is it
 * vulnerable. They sat in a detail grid and three stacked tables instead.
 *
 * The two corpus-wide tiles link to the overview page, which is where the
 * artifact and version lists actually live; the two instance-scoped tiles open
 * the tab that holds their detail. A tile that has nowhere to send the reader is
 * a plain stat, per StatBand's own rule.
 */
export function ComponentBand(props: {
    detail: ComponentDetail;
    counts: CorpusCounts | undefined;
    vulns: VulnSummary;
    active: ComponentTab;
    onSelect: (tab: ComponentTab) => void;
}) {
    const d = () => props.detail;

    const overviewHref = (): string => {
        const q = new URLSearchParams({ name: d().name });
        if (hasText(d().group)) q.set("group", d().group ?? "");
        return `/components/overview?${q.toString()}`;
    };

    // The counts arrive on their own query, so the band renders before they do.
    // An em dash says "not known yet"; a 0 would say "used nowhere", about a
    // component we are looking at inside an SBOM that contains it.
    const count = (pick: (c: CorpusCounts) => number): string | number => {
        const c = props.counts;
        return c === undefined ? "—" : pick(c);
    };

    const licenses = () => d().licenses ?? [];

    // The band mixes two scopes and used to render them identically
    // (ocidex-7gf7.7): the first two tiles count every SBOM in the corpus that
    // carries this component identity, the last two describe the single
    // component row this page is showing. Read as one set, "used by 44" next to
    // "3 licenses" invites the conclusion that the licences are the 44
    // artifacts' licences.
    const tiles = (): StatTile<ComponentTab>[] => [
        {
            head: (
                <>
                    Used by
                    <span class="tile-scope">corpus-wide</span>
                </>
            ),
            href: overviewHref(),
            value: count((c) => c.artifactCount),
            sub:
                props.counts === undefined
                    ? "artifacts"
                    : `artifacts · ${plural(props.counts.sbomCount, "SBOM")}`,
        },
        {
            head: (
                <>
                    Versions
                    <span class="tile-scope">corpus-wide</span>
                </>
            ),
            href: overviewHref(),
            value: count((c) => c.versionCount),
            sub: "distinct versions seen",
        },
        {
            id: "licenses",
            head: (
                <>
                    Licenses
                    <span class="tile-scope">this version</span>
                </>
            ),
            value: licenses().length,
            // The SPDX id is the answer for the common single-licence case;
            // listing two of five would be worse than counting them.
            sub:
                licenses().length === 1
                    ? (licenses()[0].spdxId ?? licenses()[0].name)
                    : "declared",
        },
        vulnTile<ComponentTab>(props.vulns, "vulns", "this version"),
    ];

    return <StatBand tiles={tiles()} active={props.active} onSelect={props.onSelect} />;
}
