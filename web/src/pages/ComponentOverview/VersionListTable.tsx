import { Show } from "solid-js";
import { A } from "@solidjs/router";
import PurlLink from "~/components/PurlLink";
import { VulnCountBadges } from "~/components/VulnBadge";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { plural } from "~/utils/format";
import type { VersionGroup } from "./grouping";

/** VersionListTable is the summary view: one row per version of the component. */
export function VersionListTable(props: {
    groups: VersionGroup[];
    versionHref: (version: string) => string;
}) {
    const columns = (): Column<VersionGroup>[] => [
        {
            header: "Version",
            render: (group) => (
                <>
                    <A href={props.versionHref(group.version)} class="font-mono">
                        {group.version}
                    </A>
                    <Show when={group.purl} keyed>
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
            header: "Artifacts",
            class: "text-muted",
            render: (group) => plural(group.entries.length, "artifact"),
        },
        {
            header: "Vulnerabilities",
            // Vulnerability counts are a property of the (name, version) pair,
            // so every entry in the group carries the same numbers — the first
            // is representative.
            render: (group) => (
                <VulnCountBadges
                    criticalCount={group.entries[0].criticalCount}
                    highCount={group.entries[0].highCount}
                    mediumCount={group.entries[0].mediumCount}
                    lowCount={group.entries[0].lowCount}
                    unknownCount={group.entries[0].unknownCount}
                />
            ),
        },
    ];

    return (
        <DataTable
            columns={columns()}
            rows={props.groups}
            loading={false}
            isError={false}
            emptyTitle="No versions"
            emptyMessage="No versions of this component were found."
        />
    );
}
