import type { ComponentVersionEntry } from "~/api/client";

/** One version of the component, with every SBOM instance that carries it. */
export interface VersionGroup {
    version: string;
    purl?: string;
    entries: ComponentVersionEntry[];
}

/** One artifact that contains the selected version, with its SBOM instances. */
export interface ArtifactGroup {
    key: string;
    artifactId?: string;
    artifactName?: string;
    entries: ComponentVersionEntry[];
}

export function groupByVersion(entries: ComponentVersionEntry[]): VersionGroup[] {
    const map = new Map<string, VersionGroup>();
    for (const entry of entries) {
        const key = entry.version ?? "(no version)";
        let group = map.get(key);
        if (!group) {
            group = { version: key, purl: entry.purl, entries: [] };
            map.set(key, group);
        }
        group.entries.push(entry);
    }
    return Array.from(map.values());
}

/**
 * groupByArtifact preserves the order the API returned rather than sorting, so
 * the list keeps the backend's relevance ordering. Entries without an artifact
 * id fall back to their SBOM id as the group key — an SBOM always has one, so
 * grouping never collapses unrelated rows together.
 */
export function groupByArtifact(entries: ComponentVersionEntry[]): ArtifactGroup[] {
    const order: string[] = [];
    const map = new Map<string, ArtifactGroup>();
    for (const e of entries) {
        const key = e.artifactId ?? e.sbomId;
        if (!map.has(key)) {
            order.push(key);
            map.set(key, {
                key,
                artifactId: e.artifactId ?? undefined,
                artifactName: e.artifactName ?? undefined,
                entries: [],
            });
        }
        map.get(key)?.entries.push(e);
    }
    return order.flatMap((k) => {
        const v = map.get(k);
        return v !== undefined ? [v] : [];
    });
}
