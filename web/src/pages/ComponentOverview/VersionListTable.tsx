import { For, Show } from "solid-js";
import { A } from "@solidjs/router";
import PurlLink from "~/components/PurlLink";
import { VulnCountBadges } from "~/components/VulnBadge";
import { Card } from "~/components/ui";
import { plural } from "~/utils/format";
import type { VersionGroup } from "./grouping";

/** VersionListTable is the summary view: one row per version of the component. */
export function VersionListTable(props: {
    groups: VersionGroup[];
    versionHref: (version: string) => string;
}) {
    return (
        <Card>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>Version</th>
                            <th>Artifacts</th>
                            <th>Vulnerabilities</th>
                        </tr>
                    </thead>
                    <tbody>
                        <For each={props.groups}>
                            {(group) => {
                                // Vulnerability counts are a property of the
                                // (name, version) pair, so every entry in the
                                // group carries the same numbers — the first is
                                // representative.
                                const rep = group.entries[0];
                                return (
                                    <tr>
                                        <td>
                                            <A href={props.versionHref(group.version)} class="font-mono">
                                                {group.version}
                                            </A>
                                            <Show when={group.purl} keyed>
                                                {(purl) => (
                                                    <span style={{ "margin-left": "8px" }}>
                                                        <PurlLink purl={purl} showBadge />
                                                    </span>
                                                )}
                                            </Show>
                                        </td>
                                        <td class="text-muted">{plural(group.entries.length, "artifact")}</td>
                                        <td>
                                            <VulnCountBadges
                                                criticalCount={rep.criticalCount}
                                                highCount={rep.highCount}
                                                mediumCount={rep.mediumCount}
                                                lowCount={rep.lowCount}
                                                unknownCount={rep.unknownCount}
                                            />
                                        </td>
                                    </tr>
                                );
                            }}
                        </For>
                    </tbody>
                </table>
            </div>
        </Card>
    );
}
