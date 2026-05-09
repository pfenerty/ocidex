import type { SBOMRef, ChangeSummary, ComponentDiff } from "~/api/client";
import { relativeDate } from "~/utils/format";

export function changelogRefLabel(ref: {
    id: string;
    subjectVersion?: string;
    architecture?: string;
    createdAt: string;
    buildDate?: string;
}): string {
    const label = ref.subjectVersion ?? relativeDate(ref.buildDate ?? ref.createdAt);
    return ref.architecture !== undefined ? `${label} (${ref.architecture})` : label;
}

export interface ChangelogEntryData {
    from: SBOMRef;
    to: SBOMRef;
    summary: ChangeSummary;
    changes: ComponentDiff[];
}
