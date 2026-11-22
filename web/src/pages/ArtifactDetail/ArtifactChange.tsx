import type { ArtifactVersionSummary } from "~/api/client";
import type { SeverityPoint } from "~/utils/versionDelta";

/** The table's rows as severity points, newest first. */
export function severityPoints(versions: readonly ArtifactVersionSummary[] | undefined): SeverityPoint[] {
    return (versions ?? []).map((v) => ({
        versionKey: v.versionKey,
        sbomId: v.sbomId,
        arch: v.countedSbom?.architecture,
        critical: v.vulns?.critical,
        high: v.vulns?.high,
    }));
}
