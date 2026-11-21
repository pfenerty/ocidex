/** Critical and high counts for one version; undefined when it was never scanned. */
export interface SeverityPoint {
    versionKey: string;
    critical?: number;
    high?: number;
}

/** A count's change against the version before it. */
export interface VersionDelta {
    critical?: number;
    high?: number;
}

/**
 * The variant a version key names after its number: "trixie" in
 * "3.14.9-trixie", "" for a bare "3.14.4". Semver order interleaves variants
 * (a Windows "3.14.4" lands between two Debian builds), and comparing across
 * them reports a different image's findings as a regression.
 */
export function variantOf(versionKey: string): string {
    const i = versionKey.indexOf("-");
    return i < 0 ? "" : versionKey.slice(i + 1);
}

/**
 * Deltas for a list ordered newest first, as the versions table shows it: each
 * row against the next row below it of the same variant, which is the version
 * before it. A delta is undefined when either side was never scanned, and when
 * no earlier version of that variant is on the list. A missing scan is not a
 * zero, so no delta is invented across one.
 */
export function versionDeltas(rows: readonly SeverityPoint[]): VersionDelta[] {
    return rows.map((row, i) => {
        const variant = variantOf(row.versionKey);
        const prev = rows.slice(i + 1).find((r) => variantOf(r.versionKey) === variant);
        if (prev === undefined) return {};
        return {
            critical: diff(row.critical, prev.critical),
            high: diff(row.high, prev.high),
        };
    });
}

function diff(cur: number | undefined, prev: number | undefined): number | undefined {
    return cur === undefined || prev === undefined ? undefined : cur - prev;
}

/** How the newest version compares with the one before it, for the page verdict. */
export interface Verdict {
    latest: string;
    previous: string;
    critical: number;
    delta: number;
}

/**
 * The newest scanned version against the scanned version before it of the same
 * variant. Unscanned versions are skipped rather than compared as zero, so the
 * verdict is about the two most recent versions anyone has findings for.
 */
export function latestVerdict(rows: readonly SeverityPoint[]): Verdict | undefined {
    const scanned = sameVariantAsNewest(rows);
    if (scanned.length < 2) return undefined;
    const [latest, previous] = scanned;
    const critical = latest.critical ?? 0;
    return {
        latest: latest.versionKey,
        previous: previous.versionKey,
        critical,
        delta: critical - (previous.critical ?? 0),
    };
}

/** "−2", "+14", "±0": a minus sign, not a hyphen, so it reads as a number. */
export function formatDelta(d: number): string {
    if (d === 0) return "±0";
    return d < 0 ? `−${Math.abs(d).toLocaleString()}` : `+${d.toLocaleString()}`;
}

/**
 * The scanned rows that share the newest scanned row's variant, newest first:
 * the one line of versions a verdict or a chart can honestly compare.
 */
export function sameVariantAsNewest(rows: readonly SeverityPoint[]): SeverityPoint[] {
    const scanned = rows.filter((r) => r.critical !== undefined);
    if (scanned.length === 0) return [];
    const variant = variantOf(scanned[0].versionKey);
    return scanned.filter((r) => variantOf(r.versionKey) === variant);
}

const SMALL = ["Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten"];

/**
 * A short entry written from the data, the way a dex entry describes a
 * species: how many versions are on record, whether critical findings ever
 * rose between releases, and the largest single drop. Every clause is a fact
 * the version list supports; nothing is said about versions without findings
 * data. Undefined when there are fewer than two comparable versions.
 */
export function entryText(rows: readonly SeverityPoint[], versionCount: number): string | undefined {
    const line = sameVariantAsNewest(rows).slice().reverse();
    if (line.length < 2) return undefined;
    const first = line[0];
    const last = line[line.length - 1];
    let rose = false;
    let drop = { amount: 0, version: "" };
    for (let i = 1; i < line.length; i++) {
        const d = (line[i].critical ?? 0) - (line[i - 1].critical ?? 0);
        if (d > 0) rose = true;
        if (-d > drop.amount) drop = { amount: -d, version: line[i].versionKey };
    }
    const count = versionCount <= 10 ? SMALL[versionCount] : versionCount.toLocaleString();
    const parts = [`${count} version${versionCount === 1 ? "" : "s"} on record.`];
    const span = `${(first.critical ?? 0).toLocaleString()} in ${first.versionKey}, ${(last.critical ?? 0).toLocaleString()} in ${last.versionKey}`;
    parts.push(
        rose
            ? `Critical findings rose in at least one release: ${span}.`
            : `Critical findings have not gone up in any release since ${first.versionKey}: ${span}.`,
    );
    if (drop.amount > 0) parts.push(`${drop.version} shed the most at once, ${drop.amount.toLocaleString()}.`);
    return parts.join(" ");
}
