import type { ComponentDiff, SBOMRef, ChangeSummary } from "~/api/client";
import { relativeDate } from "~/utils/format";

export function debVersionCompare(a: string, b: string): number {
    function parseDeb(v: string) {
        let epoch = 0, ver = v, rev = "";
        const ci = v.indexOf(':');
        if (ci !== -1) { epoch = parseInt(v.slice(0, ci), 10) || 0; ver = v.slice(ci + 1); }
        const di = ver.lastIndexOf('-');
        if (di !== -1) { rev = ver.slice(di + 1); ver = ver.slice(0, di); }
        return { epoch, ver, rev };
    }
    function charOrder(c: string): number {
        if (c === '~') return -1;
        if (c === '') return 0;
        if (/[a-zA-Z]/.test(c)) return c.charCodeAt(0);
        return c.charCodeAt(0) + 256;
    }
    function cmpStr(a: string, b: string): number {
        let i = 0, j = 0;
        while (i < a.length || j < b.length) {
            let ca = "", cb = "";
            while (i < a.length && !/\d/.test(a[i])) ca += a[i++];
            while (j < b.length && !/\d/.test(b[j])) cb += b[j++];
            let k = 0;
            while (k < ca.length || k < cb.length) {
                const oa = charOrder(ca[k] ?? ''), ob = charOrder(cb[k] ?? '');
                if (oa !== ob) return oa < ob ? -1 : 1;
                k++;
            }
            let na = "", nb = "";
            while (i < a.length && /\d/.test(a[i])) na += a[i++];
            while (j < b.length && /\d/.test(b[j])) nb += b[j++];
            const an = parseInt(na || "0", 10), bn = parseInt(nb || "0", 10);
            if (an !== bn) return an < bn ? -1 : 1;
        }
        return 0;
    }
    const da = parseDeb(a), db = parseDeb(b);
    if (da.epoch !== db.epoch) return da.epoch < db.epoch ? -1 : 1;
    const vc = cmpStr(da.ver, db.ver);
    if (vc !== 0) return vc;
    return cmpStr(da.rev, db.rev);
}

export function classifyChange(
    change: ComponentDiff,
): "added" | "removed" | "upgraded" | "downgraded" | "modified" {
    if (change.type !== "modified") return change.type as "added" | "removed";
    if (change.previousVersion === undefined || change.version === undefined) return "modified";
    const cmp = debVersionCompare(change.version, change.previousVersion);
    return cmp > 0 ? "upgraded" : cmp < 0 ? "downgraded" : "modified";
}

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
