import { Show } from "solid-js";
import { A } from "@solidjs/router";
import PurlLink from "~/components/PurlLink";
import { VulnCountBadges } from "~/components/VulnBadge";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { plural } from "~/utils/format";
import type { ComponentVersionSummary } from "~/api/client";

/** NO_VERSION labels the group of occurrences that carry no version string. */
export const NO_VERSION = "(no version)";

/** VersionListTable is the summary view: one row per version of the component. */
export function VersionListTable(props: {
    versions: ComponentVersionSummary[];
    versionHref: (version: string) => string;
}) {
    const columns = (): Column<ComponentVersionSummary>[] => [
        {
            header: "Version",
            render: (v) => (
                <>
                    <A href={props.versionHref(v.version ?? NO_VERSION)} class="font-mono">
                        {v.version ?? NO_VERSION}
                    </A>
                    <Show when={v.purl} keyed>
                        {(purl) => (
                            <span class="ml-2">
                                <PurlLink purl={purl} showBadge />
                            </span>
                        )}
                    </Show>
                </>
            ),
        },
        {
            header: "SBOMs",
            class: "text-muted",
            render: (v) => plural(v.sbomCount, "SBOM"),
        },
        {
            header: "Artifacts",
            class: "text-muted",
            render: (v) => plural(v.artifactCount, "artifact"),
        },
        {
            header: "Vulnerabilities",
            render: (v) => (
                <VulnCountBadges
                    criticalCount={v.criticalCount}
                    highCount={v.highCount}
                    mediumCount={v.mediumCount}
                    lowCount={v.lowCount}
                    unknownCount={v.unknownCount}
                />
            ),
        },
    ];

    return (
        <DataTable
            columns={columns()}
            rows={props.versions}
            loading={false}
            isError={false}
            emptyTitle="No versions"
            emptyMessage="No versions of this component were found."
        />
    );
}
