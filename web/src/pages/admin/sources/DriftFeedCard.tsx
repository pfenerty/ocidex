import { A } from "@solidjs/router";
import { CardHeader } from "~/components/ui";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { TimestampCell } from "~/components/cells";
import { signingStatusLabel, driftReasonLabel } from "~/utils/trust";
import { useRecentDrift } from "~/api/queries";
import type { RecentDriftEntry } from "~/api/client";

const columns: Column<RecentDriftEntry>[] = [
    {
        header: "Detected",
        sortKey: "detectedAt",
        sortType: "numeric",
        sortValue: (e) => e.detectedAt,
        render: (e) => <TimestampCell iso={e.detectedAt} />,
    },
    {
        header: "Registry",
        sortKey: "registryName",
        sortValue: (e) => e.registryName ?? "",
        render: (e) => e.registryName ?? "—",
    },
    {
        header: "Artifact",
        sortKey: "artifactName",
        sortValue: (e) => e.artifactName ?? e.sbomId,
        render: (e) => <A href={`/sboms/${e.sbomId}`}>{e.artifactName ?? e.sbomId}</A>,
    },
    {
        header: "Change",
        render: (e) => (
            <>
                {signingStatusLabel(e.previousStatus)} → {signingStatusLabel(e.newStatus)}
            </>
        ),
    },
    {
        header: "Reason",
        render: (e) => <span class="text-muted">{driftReasonLabel(e.reason)}</span>,
    },
];

/** DriftFeedCard is the regression-only provenance drift feed (ADR-037). */
export function DriftFeedCard() {
    const recentDrift = useRecentDrift(() => ({ limit: 20 }));

    return (
        <DataTable
            class="mt-6"
            caption={
                <>
                    <CardHeader title="Recent Provenance Drift" />
                    {/* The caption travels into the empty and error branches
                        too, which is the point: "no drift events" only means
                        something once you know the feed is regression-only. */}
                    <p class="text-muted text-sm mb-3">
                        Drift tracking is regression-only: it records when a re-verified
                        artifact&apos;s signing status gets worse (e.g. verified → verification
                        failed). Recovery transitions such as unsigned → verified are not
                        recorded here.
                    </p>
                </>
            }
            columns={columns}
            rows={recentDrift.data?.data ?? undefined}
            loading={recentDrift.isFetching}
            isError={recentDrift.isError}
            error={recentDrift.error}
            emptyTitle="No drift events recorded"
        />
    );
}
