/**
 * The version key the server gives every SBOM with no version of its own (a
 * digest-only scan), so they share one row instead of one each. Parentheses
 * cannot appear in an OCI tag, so no real version collides with it.
 */
export const UNTAGGED_VERSION = "(untagged)";

/** Critical and high counts for one version; undefined when it was never scanned. */
export interface SeverityPoint {
    versionKey: string;
    /** The SBOM the counts were taken from, where known: what a comparison opens. */
    sbomId?: string;
    /**
     * The architecture the counts were taken from (the version's counted SBOM).
     * Architectures carry different packages, so two versions' counts compare
     * only when they were taken from the same one. Undefined when unknown, as
     * for a non-image artifact; two unknowns compare.
     */
    arch?: string;
    critical?: number;
    high?: number;
}

/**
 * A list row's or featured card's critical history as severity points. The
 * server omits an unknown architecture or sends it empty; both mean unknown.
 */
export function historyPoints(
    history: readonly { versionKey: string; critical?: number; architecture?: string }[] | null | undefined,
): SeverityPoint[] {
    return (history ?? []).map((h) => ({
        versionKey: h.versionKey,
        arch: h.architecture === "" ? undefined : h.architecture,
        critical: h.critical,
    }));
}

/** A count's change against the version before it. */
export interface VersionDelta {
    critical?: number;
    high?: number;
    /** An earlier version of the variant exists, but none counted on this one's architecture. */
    noSharedArch?: boolean;
}

/** Whether two versions' counts were taken from the same architecture. */
function sameArch(a: SeverityPoint, b: SeverityPoint): boolean {
    return a.arch === b.arch;
}

const PRERELEASE = /^(rc|pre|alpha|beta|dev)(\.?\d+)?$/i;

/**
 * The variant a version key names after its number: "trixie" in
 * "3.14.9-trixie", "" for a bare "3.14.4". Semver order interleaves variants
 * (a Windows "3.14.4" lands between two Debian builds), and comparing across
 * them reports a different image's findings as a regression. A prerelease tag
 * ("-rc.1", "-pre.4") is not a variant: it is on the plain line.
 *
 * The server applies the same rule (sbom.version_variant, service.VersionLine);
 * versionLine.golden.json holds the cases all of them are tested against.
 */
export function variantOf(versionKey: string): string {
    const i = versionKey.indexOf("-");
    if (i < 0) return "";
    const suffix = versionKey.slice(i + 1);
    return PRERELEASE.test(suffix) ? "" : suffix;
}

/**
 * Deltas for a list ordered newest first, as the versions table shows it: each
 * row against the next row below it of the same variant counted on the same
 * architecture, which is the version before it. A delta is undefined when
 * either side was never scanned, and when no such earlier version is on the
 * list. A missing scan is not a zero, so no delta is invented across one; a
 * riscv64-only build is not compared with an amd64 one either.
 */
export function versionDeltas(rows: readonly SeverityPoint[]): VersionDelta[] {
    return rows.map((row, i) => {
        const { prev, line } = predecessor(rows, i);
        if (prev === undefined) return line > 0 ? { noSharedArch: true } : {};
        return {
            critical: diff(row.critical, prev.critical),
            high: diff(row.high, prev.high),
        };
    });
}

/**
 * The version a row is compared with: the next row below it of the same
 * variant counted on the same architecture. line is how many rows of the
 * variant lie below it at all, so a caller can tell "nothing earlier" from
 * "nothing earlier on this architecture".
 */
function predecessor(rows: readonly SeverityPoint[], i: number): { prev?: SeverityPoint; line: number } {
    const row = rows[i];
    const variant = variantOf(row.versionKey);
    const below = rows.slice(i + 1).filter((r) => variantOf(r.versionKey) === variant);
    return { prev: below.find((r) => sameArch(r, row)), line: below.length };
}

/** A version's critical count against the version it is compared with. */
export interface CriticalChange {
    /** The version compared against. */
    previous: string;
    delta: number;
    /** The two SBOMs compared, where known, so the change can open as a diff. */
    fromSbomId?: string;
    toSbomId?: string;
}

/**
 * How one version's critical count changed from the version it is compared
 * with, by the versions table's rule (versionDeltas). For the artifact's
 * headline version, so the tile states the change of the version it counts
 * rather than of whichever row happens to be newest. Undefined when the
 * version is not on the list, either side was never scanned, or nothing
 * earlier is comparable.
 */
export function criticalChange(rows: readonly SeverityPoint[], versionKey: string): CriticalChange | undefined {
    const i = rows.findIndex((r) => r.versionKey === versionKey);
    if (i < 0) return undefined;
    const { prev } = predecessor(rows, i);
    const delta = prev === undefined ? undefined : diff(rows[i].critical, prev.critical);
    return prev === undefined || delta === undefined
        ? undefined
        : { previous: prev.versionKey, delta, fromSbomId: prev.sbomId, toSbomId: rows[i].sbomId };
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
 * The scanned rows that share the newest scanned row's variant and counted
 * architecture, newest first: the one line of versions a verdict or a chart
 * can honestly compare.
 */
export function sameVariantAsNewest(rows: readonly SeverityPoint[]): SeverityPoint[] {
    const scanned = rows.filter((r) => r.critical !== undefined);
    if (scanned.length === 0) return [];
    const newest = scanned[0];
    const variant = variantOf(newest.versionKey);
    return scanned.filter((r) => variantOf(r.versionKey) === variant && sameArch(r, newest));
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

/** The major version a key starts with, or undefined when it has none. */
function majorOf(versionKey: string): number | undefined {
    const m = /^v?(\d{1,9})(?!\d)/.exec(versionKey);
    return m === null ? undefined : Number(m[1]);
}

/**
 * The part of a variant that names its base image: "trixie" in "slim-trixie",
 * "alpine" in "alpine3.20". Point releases of one base are the same line;
 * bookworm to trixie is not.
 */
function baseOf(versionKey: string): string {
    const variant = variantOf(versionKey);
    const last = variant.slice(variant.lastIndexOf("-") + 1);
    return last.replace(/[\d.]+$/, "");
}

/**
 * The evolution line a version belongs to: its major version and its
 * variant's base. Versions with no major version share one line of their own,
 * which never evolves into or out of anything.
 */
export function evolutionLine(versionKey: string): string {
    const major = majorOf(versionKey);
    return major === undefined ? "" : `${major}|${baseOf(versionKey)}`;
}

/**
 * The label for the boundary between two adjacent lines of a newest-first
 * list, "evolved · 2.x → 3.0" or "evolved · bookworm → trixie": the older
 * line on the left, the first version of the newer one on the right.
 * Undefined when either side has no major version.
 */
export function evolutionLabel(olderKey: string, newerFirstKey: string): string | undefined {
    const older = majorOf(olderKey);
    const newer = majorOf(newerFirstKey);
    if (older === undefined || newer === undefined) return undefined;
    if (older !== newer) return `evolved · ${older}.x → ${newerFirstKey.replace(/^v/, "")}`;
    const from = baseOf(olderKey);
    const to = baseOf(newerFirstKey);
    return from === to ? undefined : `evolved · ${from === "" ? "plain" : from} → ${to === "" ? "plain" : to}`;
}
