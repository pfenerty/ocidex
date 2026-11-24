import type { SBOMRef, ChangeSummary, ComponentDiff } from "~/api/client";
import type { components } from "~/types/openapi";

/** CVEs a release closed and opened, by severity. */
export type ChangelogVulnTotals = components["schemas"]["ChangelogVulnTotals"];
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
    /** Present on changelog and diff responses that matched vulnerabilities. */
    vulns?: ChangelogVulnTotals;
}
