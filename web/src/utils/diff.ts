import type { SBOMRef, ChangeSummary, ComponentDiff } from "~/api/client";
import { relativeDate } from "~/utils/format";

export function changelogRefLabel(ref: {
    id: string;
    subjectVersion?: string;
    architecture?: string;
    flavor?: string;
    createdAt: string;
    buildDate?: string;
}): string {
    const base = ref.subjectVersion ?? relativeDate(ref.buildDate ?? ref.createdAt);
    return [base, ref.architecture, ref.flavor].filter(Boolean).join(" · ");
}

export interface ChangelogEntryData {
    from: SBOMRef;
    to: SBOMRef;
    summary: ChangeSummary;
    changes: ComponentDiff[];
}
