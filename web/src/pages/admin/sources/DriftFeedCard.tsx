import { For, Show } from "solid-js";
import { A } from "@solidjs/router";
import { Card, CardHeader } from "~/components/ui";
import { formatDateTime } from "~/utils/format";
import { signingStatusLabel, driftReasonLabel } from "~/utils/trust";
import { useRecentDrift } from "~/api/queries";

/** DriftFeedCard is the regression-only provenance drift feed (ADR-037). */
export function DriftFeedCard() {
    const recentDrift = useRecentDrift(() => ({ limit: 20 }));

    return (
        <Card style={{ "margin-top": "1.5rem" }}>
            <CardHeader title="Recent Provenance Drift" />
            <p style={{ color: "var(--color-text-muted)", "font-size": "0.85rem", "margin-bottom": "0.75rem" }}>
                Drift tracking is regression-only: it records when a re-verified artifact's
                signing status gets worse (e.g. verified → verification failed). Recovery
                transitions such as unsigned → verified are not recorded here.
            </p>
            <Show
                when={(recentDrift.data?.data?.length ?? 0) > 0}
                fallback={<p style={{ color: "var(--color-text-muted)" }}>No drift events recorded.</p>}
            >
                <table class="table">
                    <thead>
                        <tr>
                            <th>Detected</th>
                            <th>Registry</th>
                            <th>Artifact</th>
                            <th>Change</th>
                            <th>Reason</th>
                        </tr>
                    </thead>
                    <tbody>
                        <For each={recentDrift.data?.data ?? []}>
                            {(entry) => (
                                <tr>
                                    <td style={{ "font-size": "0.85rem" }}>{formatDateTime(entry.detectedAt)}</td>
                                    <td>{entry.registryName ?? "—"}</td>
                                    <td>
                                        <A href={`/sboms/${entry.sbomId}`} style={{ "font-size": "0.85rem" }}>
                                            {entry.artifactName ?? entry.sbomId}
                                        </A>
                                    </td>
                                    <td style={{ "font-size": "0.85rem" }}>
                                        {signingStatusLabel(entry.previousStatus)} → {signingStatusLabel(entry.newStatus)}
                                    </td>
                                    <td style={{ color: "var(--color-text-muted)", "font-size": "0.85rem" }}>
                                        {driftReasonLabel(entry.reason)}
                                    </td>
                                </tr>
                            )}
                        </For>
                    </tbody>
                </table>
            </Show>
        </Card>
    );
}
