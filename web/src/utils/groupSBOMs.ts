import type { SBOMSummary } from "~/api/client";

/**
 * Group SBOMs by version key, then by architecture.
 * Only the first (newest) SBOM per (version, arch) pair is kept —
 * assumes the caller provides rows sorted by created_at DESC.
 */
export function groupSBOMsByVersionAndArch(sboms: SBOMSummary[]): {
    versionOrder: string[];
    versionMap: Map<string, Map<string, SBOMSummary>>;
} {
    const versionOrder: string[] = [];
    const versionMap = new Map<string, Map<string, SBOMSummary>>();
    for (const sbom of sboms) {
        if (sbom.architecture === undefined) continue;
        const vKey = sbom.subjectVersion ?? sbom.imageVersion ?? sbom.id;
        if (!versionMap.has(vKey)) {
            versionOrder.push(vKey);
            versionMap.set(vKey, new Map());
        }
        const archMap = versionMap.get(vKey);
        if (archMap !== undefined && !archMap.has(sbom.architecture)) {
            archMap.set(sbom.architecture, sbom);
        }
    }
    return { versionOrder, versionMap };
}
