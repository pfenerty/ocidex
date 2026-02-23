import { createSignal, Show, For } from "solid-js";
import { A, useParams } from "@solidjs/router";
import {
    useArtifact,
    useArtifactSBOMs,
    useArtifactChangelog,
    useArtifactLicenseSummary,
} from "~/api/queries";
import type {
    SBOMSummary,
    SBOMRef,
    ChangeSummary,
    ComponentDiff,
    LicenseCount,
    PaginationMeta,
} from "~/api/client";
import { Loading, ErrorBox, EmptyState } from "~/components/Feedback";
import Pagination from "~/components/Pagination";
import PurlLink from "~/components/PurlLink";
import { purlToRegistryUrl, purlTypeLabel } from "~/utils/purl";
import {
    artifactDisplayName,
    sbomShortLabel,
    formatDateTime,
    relativeDate,
    shortDigest,
    plural,
} from "~/utils/format";
import { containerRegistryUrl, detectRegistry } from "~/utils/oci";

export default function ArtifactDetail() {
    const params = useParams<{ id: string }>();
    const [sbomOffset, setSbomOffset] = createSignal(0);
    const [tab, setTab] = createSignal<"sboms" | "changelog" | "licenses">(
        "sboms",
    );
    const [selectedArch, setSelectedArch] = createSignal<string | undefined>(undefined);
    const sbomLimit = 25;

    const artifactQuery = useArtifact(() => params.id);

    const sbomsQuery = useArtifactSBOMs(
        () => params.id,
        () => ({ limit: sbomLimit, offset: sbomOffset() }),
    );

    const changelogQuery = useArtifactChangelog(() => params.id, {
        enabled: () => tab() === "changelog",
        arch: selectedArch,
    });

    const licenseQuery = useArtifactLicenseSummary(() => params.id, {
        enabled: () => tab() === "licenses",
    });

    return (
        <>
            <div class="breadcrumb">
                <A href="/artifacts">Artifacts</A>
                <span class="separator">/</span>
                <span>{artifactQuery.data?.name ?? params.id}</span>
            </div>

            <Show when={!artifactQuery.isLoading} fallback={<Loading />}>
                <Show
                    when={!artifactQuery.isError}
                    fallback={<ErrorBox error={artifactQuery.error} />}
                >
                    {(() => {
                        const a = artifactQuery.data!;
                        return (
                            <>
                                <div class="page-header">
                                    <div class="page-header-row">
                                        <div>
                                            <h2>
                                                <Show
                                                    when={
                                                        a.type ===
                                                            "container" &&
                                                        detectRegistry(
                                                            a.name,
                                                        ) !== "redhat"
                                                    }
                                                    fallback={artifactDisplayName(
                                                        a,
                                                    )}
                                                >
                                                    <a
                                                        href={containerRegistryUrl(
                                                            a.name,
                                                        )}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                    >
                                                        {artifactDisplayName(a)}
                                                    </a>
                                                </Show>
                                            </h2>
                                            <p class="text-muted">
                                                <span class="badge">
                                                    {a.type}
                                                </span>{" "}
                                                {plural(a.sbomCount, "SBOM")}
                                                {" · First tracked "}
                                                {relativeDate(a.createdAt)}
                                            </p>
                                        </div>
                                        <div class="btn-group">
                                            <Show
                                                when={
                                                    a.purl &&
                                                    purlToRegistryUrl(a.purl)
                                                }
                                            >
                                                <a
                                                    href={
                                                        purlToRegistryUrl(
                                                            a.purl!,
                                                        )!
                                                    }
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    class="btn btn-sm btn-primary"
                                                >
                                                    View on{" "}
                                                    {purlTypeLabel(a.purl!) ??
                                                        "Registry"}
                                                </a>
                                            </Show>
                                            <A
                                                href={`/diff`}
                                                class="btn btn-sm"
                                            >
                                                Compare SBOMs
                                            </A>
                                        </div>
                                    </div>
                                </div>

                                <div class="card mb-md">
                                    <div class="card-header">
                                        <h3>About this Artifact</h3>
                                    </div>
                                    <div class="detail-grid">
                                        <div class="detail-field">
                                            <span class="detail-label">
                                                Name
                                            </span>
                                            <span class="detail-value">
                                                {a.name}
                                            </span>
                                        </div>
                                        <div class="detail-field">
                                            <span class="detail-label">
                                                Type
                                            </span>
                                            <span class="detail-value">
                                                {a.type}
                                            </span>
                                        </div>
                                        <Show when={a.group}>
                                            <div class="detail-field">
                                                <span class="detail-label">
                                                    Group
                                                </span>
                                                <span class="detail-value">
                                                    {a.group}
                                                </span>
                                            </div>
                                        </Show>
                                        <Show when={a.purl}>
                                            <div class="detail-field">
                                                <span class="detail-label">
                                                    Package URL
                                                </span>
                                                <span class="detail-value">
                                                    <PurlLink
                                                        purl={a.purl!}
                                                        showBadge
                                                    />
                                                </span>
                                            </div>
                                        </Show>
                                        <Show when={a.cpe}>
                                            <div class="detail-field">
                                                <span class="detail-label">
                                                    CPE
                                                </span>
                                                <span class="detail-value mono text-sm">
                                                    {a.cpe}
                                                </span>
                                            </div>
                                        </Show>
                                        <div class="detail-field">
                                            <span class="detail-label">
                                                First Tracked
                                            </span>
                                            <span class="detail-value">
                                                {formatDateTime(a.createdAt)}
                                            </span>
                                        </div>
                                    </div>
                                    <details class="mt-md">
                                        <summary
                                            class="text-muted text-sm"
                                            style={{ cursor: "pointer" }}
                                        >
                                            Internal ID
                                        </summary>
                                        <p
                                            class="mono text-sm mt-sm"
                                            style={{
                                                "word-break": "break-all",
                                            }}
                                        >
                                            {a.id}
                                        </p>
                                    </details>
                                </div>

                                <div class="tab-bar">
                                    <button
                                        class={
                                            tab() === "sboms" ? "active" : ""
                                        }
                                        onClick={() => setTab("sboms")}
                                    >
                                        SBOMs ({a.sbomCount})
                                    </button>
                                    <button
                                        class={
                                            tab() === "changelog"
                                                ? "active"
                                                : ""
                                        }
                                        onClick={() => setTab("changelog")}
                                    >
                                        Changelog
                                    </button>
                                    <button
                                        class={
                                            tab() === "licenses" ? "active" : ""
                                        }
                                        onClick={() => setTab("licenses")}
                                    >
                                        Licenses
                                    </button>
                                </div>

                                <Show when={tab() === "sboms"}>
                                    <Show
                                        when={!sbomsQuery.isLoading}
                                        fallback={<Loading />}
                                    >
                                        <Show
                                            when={!sbomsQuery.isError}
                                            fallback={
                                                <ErrorBox
                                                    error={sbomsQuery.error}
                                                />
                                            }
                                        >
                                            <Show
                                                when={
                                                    sbomsQuery.data &&
                                                    sbomsQuery.data.data
                                                        .length > 0
                                                }
                                                fallback={
                                                    <EmptyState
                                                        title="No SBOMs yet"
                                                        message="Ingest a CycloneDX SBOM for this artifact to see it here."
                                                    />
                                                }
                                            >
                                                <SBOMsTab
                                                    sboms={
                                                        sbomsQuery.data!.data
                                                    }
                                                    pagination={
                                                        sbomsQuery.data!
                                                            .pagination
                                                    }
                                                    artifactName={a.name}
                                                    artifactType={a.type}
                                                    onPageChange={setSbomOffset}
                                                />
                                            </Show>
                                        </Show>
                                    </Show>
                                </Show>

                                <Show when={tab() === "changelog"}>
                                    <Show
                                        when={!changelogQuery.isLoading}
                                        fallback={<Loading />}
                                    >
                                        <Show
                                            when={!changelogQuery.isError}
                                            fallback={
                                                <ErrorBox
                                                    error={changelogQuery.error}
                                                />
                                            }
                                        >
                                            <Show
                                                when={
                                                    changelogQuery.data &&
                                                    changelogQuery.data.entries
                                                        .length > 0
                                                }
                                                fallback={
                                                    <EmptyState
                                                        title="No changes detected"
                                                        message="At least two SBOMs are needed to generate a changelog. Ingest another SBOM for this artifact to see what changed."
                                                    />
                                                }
                                            >
                                                <ChangelogTab
                                                    entries={
                                                        changelogQuery.data!
                                                            .entries
                                                    }
                                                    availableArchitectures={
                                                        changelogQuery.data!
                                                            .availableArchitectures ?? []
                                                    }
                                                    selectedArch={selectedArch()}
                                                    onArchChange={setSelectedArch}
                                                />
                                            </Show>
                                        </Show>
                                    </Show>
                                </Show>

                                <Show when={tab() === "licenses"}>
                                    <Show
                                        when={!licenseQuery.isLoading}
                                        fallback={<Loading />}
                                    >
                                        <Show
                                            when={!licenseQuery.isError}
                                            fallback={
                                                <ErrorBox
                                                    error={licenseQuery.error}
                                                />
                                            }
                                        >
                                            <Show
                                                when={
                                                    licenseQuery.data &&
                                                    licenseQuery.data.licenses
                                                        .length > 0
                                                }
                                                fallback={
                                                    <EmptyState
                                                        title="No license data"
                                                        message="No license information found for this artifact's latest SBOM."
                                                    />
                                                }
                                            >
                                                <LicensesTab
                                                    licenses={
                                                        licenseQuery.data!
                                                            .licenses
                                                    }
                                                />
                                            </Show>
                                        </Show>
                                    </Show>
                                </Show>
                            </>
                        );
                    })()}
                </Show>
            </Show>
        </>
    );
}

function CopyDigest(props: {
    digest: string;
    artifactName: string;
    isContainer: boolean;
}) {
    const [copied, setCopied] = createSignal(false);

    const ref = () =>
        props.isContainer
            ? `${props.artifactName}@${props.digest}`
            : props.digest;

    const copy = async () => {
        try {
            await navigator.clipboard.writeText(ref());
        } catch {
            // Fallback for non-HTTPS contexts
            const ta = document.createElement("textarea");
            ta.value = ref();
            ta.style.position = "fixed";
            ta.style.opacity = "0";
            document.body.appendChild(ta);
            ta.select();
            document.execCommand("copy");
            document.body.removeChild(ta);
        }
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
    };

    return (
        <button
            type="button"
            class="copy-btn mono text-sm"
            title={`Click to copy: ${ref()}`}
            onClick={copy}
        >
            {copied() ? "Copied!" : shortDigest(props.digest)}
        </button>
    );
}

function SBOMsTab(props: {
    sboms: SBOMSummary[];
    pagination: PaginationMeta;
    artifactName: string;
    artifactType: string;
    onPageChange: (offset: number) => void;
}) {
    const isContainer = () => props.artifactType === "container";
    const hasArch = () => props.sboms.some((s) => s.architecture != null);

    // Group by effective version key, preserving API order (newest first).
    const groups = () => {
        if (!hasArch()) return null;
        const order: string[] = [];
        const map = new Map<string, SBOMSummary[]>();
        for (const sbom of props.sboms) {
            if (!sbom.architecture) continue;
            const key = sbom.subjectVersion ?? sbom.imageVersion ?? sbom.id;
            if (!map.has(key)) { order.push(key); map.set(key, []); }
            map.get(key)!.push(sbom);
        }
        return { order, map };
    };

    return (
        <div class="card">
            <div class="table-wrapper">
                <Show
                    when={hasArch()}
                    fallback={
                        <table>
                            <thead>
                                <tr>
                                    <th>Version</th>
                                    <th>Components</th>
                                    <th>Digest</th>
                                    <th>Build Date</th>
                                </tr>
                            </thead>
                            <tbody>
                                <For each={props.sboms}>
                                    {(sbom) => (
                                        <tr>
                                            <td>
                                                <A href={`/sboms/${sbom.id}`}>
                                                    {sbomShortLabel(sbom)}
                                                </A>
                                            </td>
                                            <td>
                                                <Show
                                                    when={sbom.componentCount != null}
                                                    fallback={<span class="text-muted">—</span>}
                                                >
                                                    {plural(sbom.componentCount!, "component")}
                                                </Show>
                                            </td>
                                            <td>
                                                <Show
                                                    when={sbom.digest}
                                                    fallback={<span class="text-muted">—</span>}
                                                >
                                                    <CopyDigest
                                                        digest={sbom.digest!}
                                                        artifactName={props.artifactName}
                                                        isContainer={isContainer()}
                                                    />
                                                </Show>
                                            </td>
                                            <td
                                                class="nowrap text-muted"
                                                title={new Date(sbom.buildDate ?? sbom.createdAt).toLocaleString()}
                                            >
                                                {relativeDate(sbom.buildDate ?? sbom.createdAt)}
                                            </td>
                                        </tr>
                                    )}
                                </For>
                            </tbody>
                        </table>
                    }
                >
                    <table>
                        <thead>
                            <tr>
                                <th>Version</th>
                                <th>Architectures</th>
                                <th>Build Date</th>
                            </tr>
                        </thead>
                        <tbody>
                            <For each={groups()!.order}>
                                {(key) => {
                                    const archs = groups()!.map.get(key)!;
                                    const newest = archs.reduce((a, b) =>
                                        new Date(a.buildDate ?? a.createdAt) > new Date(b.buildDate ?? b.createdAt) ? a : b
                                    );
                                    const preferred = archs.find(s => s.architecture === "amd64") ?? archs[0];
                                    return (
                                        <>
                                            <tr style={{ "font-weight": "600" }}>
                                                <td>
                                                    <A href={`/sboms/${preferred.id}`}>
                                                        {preferred.subjectVersion ?? preferred.imageVersion ?? key}
                                                    </A>
                                                </td>
                                                <td>
                                                    <For each={archs}>
                                                        {(s) => (
                                                            <span class="badge badge-primary" style={{ "margin-right": "4px" }}>
                                                                {s.architecture}
                                                            </span>
                                                        )}
                                                    </For>
                                                </td>
                                                <td
                                                    class="nowrap text-muted"
                                                    title={new Date(newest.buildDate ?? newest.createdAt).toLocaleString()}
                                                >
                                                    {relativeDate(newest.buildDate ?? newest.createdAt)}
                                                </td>
                                            </tr>
                                            <For each={archs}>
                                                {(s) => (
                                                    <tr style={{ "background": "var(--color-bg-alt, #f8f9fa)" }}>
                                                        <td colspan={3} style={{ "padding-left": "2rem" }}>
                                                            <span class="badge badge-primary" style={{ "margin-right": "8px" }}>
                                                                {s.architecture}
                                                            </span>
                                                            <A href={`/sboms/${s.id}`} style={{ "margin-right": "12px" }}>
                                                                {plural(s.componentCount ?? 0, "component")}
                                                            </A>
                                                            <Show when={s.digest}>
                                                                <CopyDigest
                                                                    digest={s.digest!}
                                                                    artifactName={props.artifactName}
                                                                    isContainer={isContainer()}
                                                                />
                                                            </Show>
                                                        </td>
                                                    </tr>
                                                )}
                                            </For>
                                        </>
                                    );
                                }}
                            </For>
                            <For each={props.sboms.filter((s) => !s.architecture)}>
                                {(sbom) => (
                                    <tr>
                                        <td>
                                            <A href={`/sboms/${sbom.id}`}>
                                                {sbomShortLabel(sbom)}
                                            </A>
                                        </td>
                                        <td>
                                            <Show
                                                when={sbom.componentCount != null}
                                                fallback={<span class="text-muted">—</span>}
                                            >
                                                {plural(sbom.componentCount!, "component")}
                                            </Show>
                                        </td>
                                        <td
                                            class="nowrap text-muted"
                                            title={new Date(sbom.buildDate ?? sbom.createdAt).toLocaleString()}
                                        >
                                            {relativeDate(sbom.buildDate ?? sbom.createdAt)}
                                        </td>
                                    </tr>
                                )}
                            </For>
                        </tbody>
                    </table>
                </Show>
            </div>
            <Pagination
                pagination={props.pagination}
                onPageChange={props.onPageChange}
            />
        </div>
    );
}

const categoryColors: Record<string, { bg: string; label: string }> = {
    permissive: { bg: "var(--color-success)", label: "Permissive" },
    "weak-copyleft": { bg: "var(--color-warning)", label: "Weak Copyleft" },
    copyleft: { bg: "var(--color-danger)", label: "Copyleft" },
    unknown: { bg: "var(--color-text-dim)", label: "Unknown" },
};

function LicensesTab(props: { licenses: LicenseCount[] }) {
    const total = () =>
        props.licenses.reduce(
            (acc: number, l: LicenseCount) => acc + l.componentCount,
            0,
        );
    const byCat = () =>
        props.licenses.reduce(
            (acc: Record<string, number>, l: LicenseCount) => {
                acc[l.category] = (acc[l.category] || 0) + l.componentCount;
                return acc;
            },
            {} as Record<string, number>,
        );
    const hasCopyleft = () => (byCat().copyleft || 0) > 0;

    return (
        <>
            <Show when={hasCopyleft()}>
                <div class="alert alert-danger mb-md">
                    <strong>Copyleft licenses detected.</strong> Review the
                    licenses below for compliance requirements.
                </div>
            </Show>

            <div class="license-bar mb-md">
                <For each={Object.entries(byCat())}>
                    {([cat, count]) => (
                        <div
                            class="license-bar-segment"
                            style={{
                                width: `${((count) / total()) * 100}%`,
                                background: categoryColors[cat]?.bg ?? "gray",
                            }}
                            title={`${categoryColors[cat]?.label ?? cat}: ${plural(count, "component")}`}
                        />
                    )}
                </For>
            </div>

            <div class="license-legend mb-md">
                <For each={Object.entries(byCat())}>
                    {([cat, count]) => (
                        <span class="license-legend-item">
                            <span
                                class="license-dot"
                                style={{
                                    background:
                                        categoryColors[cat]?.bg ?? "gray",
                                }}
                            />
                            {categoryColors[cat]?.label ?? cat} (
                            {count})
                        </span>
                    )}
                </For>
            </div>

            <div class="card">
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>License</th>
                                <th>SPDX ID</th>
                                <th>Category</th>
                                <th>Components</th>
                            </tr>
                        </thead>
                        <tbody>
                            <For each={props.licenses}>
                                {(lic) => (
                                    <tr>
                                        <td>
                                            <A
                                                href={`/licenses/${lic.id}/components`}
                                            >
                                                {lic.name}
                                            </A>
                                        </td>
                                        <td>
                                            <Show
                                                when={lic.spdxId}
                                                fallback={
                                                    <span class="text-muted">
                                                        —
                                                    </span>
                                                }
                                            >
                                                <span class="badge badge-primary">
                                                    {lic.spdxId}
                                                </span>
                                            </Show>
                                        </td>
                                        <td>
                                            <span
                                                class={`badge ${
                                                    lic.category === "copyleft"
                                                        ? "badge-danger"
                                                        : lic.category ===
                                                            "weak-copyleft"
                                                          ? "badge-warning"
                                                          : lic.category ===
                                                              "permissive"
                                                            ? "badge-success"
                                                            : ""
                                                }`}
                                            >
                                                {categoryColors[lic.category]
                                                    ?.label ?? lic.category}
                                            </span>
                                        </td>
                                        <td>{lic.componentCount}</td>
                                    </tr>
                                )}
                            </For>
                        </tbody>
                    </table>
                </div>
            </div>
        </>
    );
}

function debVersionCompare(a: string, b: string): number {
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

function classifyChange(
    change: ComponentDiff,
): "added" | "removed" | "upgraded" | "downgraded" | "modified" {
    if (change.type !== "modified") return change.type as "added" | "removed";
    if (!change.previousVersion || !change.version) return "modified";
    const cmp = debVersionCompare(change.version, change.previousVersion);
    return cmp > 0 ? "upgraded" : cmp < 0 ? "downgraded" : "modified";
}

function changelogRefLabel(ref: {
    id: string;
    subjectVersion?: string;
    architecture?: string;
    createdAt: string;
    buildDate?: string;
}): string {
    const label = ref.subjectVersion ?? relativeDate(ref.buildDate ?? ref.createdAt);
    return ref.architecture ? `${label} (${ref.architecture})` : label;
}

interface ChangelogEntryData {
    from: SBOMRef;
    to: SBOMRef;
    summary: ChangeSummary;
    changes: ComponentDiff[];
}

function ChangelogTab(props: {
    entries: ChangelogEntryData[];
    availableArchitectures: string[];
    selectedArch: string | undefined;
    onArchChange: (arch: string) => void;
}) {
    const effectiveArch = () =>
        props.selectedArch ?? props.availableArchitectures[0];
    const [packagesOnly, setPackagesOnly] = createSignal(true);
    const [typeFilter, setTypeFilter] = createSignal<string | null>(null);
    const [nameFilter, setNameFilter] = createSignal("");
    const toggleTypeFilter = (kind: string) =>
        setTypeFilter(prev => prev === kind ? null : kind);

    return (
        <>
        <Show when={props.availableArchitectures.length > 1}>
            <div class="tab-bar mb-md">
                <For each={props.availableArchitectures}>
                    {(arch) => (
                        <button
                            class={effectiveArch() === arch ? "active" : ""}
                            onClick={() => props.onArchChange(arch)}
                        >
                            {arch}
                        </button>
                    )}
                </For>
            </div>
        </Show>
        <div class="mb-md" style={{ display: "flex", "align-items": "center", gap: "8px", "flex-wrap": "wrap" }}>
            <label style={{ display: "flex", "align-items": "center", gap: "6px", cursor: "pointer", "font-size": "0.875rem" }}>
                <input
                    type="checkbox"
                    checked={packagesOnly()}
                    onChange={(e) => setPackagesOnly(e.target.checked)}
                />
                Packages only
            </label>
            <input
                type="text"
                placeholder="Filter by package…"
                value={nameFilter()}
                onInput={(e) => setNameFilter(e.currentTarget.value)}
                style={{ flex: "1", "min-width": "160px", "font-size": "0.875rem" }}
            />
        </div>
        <For each={props.entries}>
            {(entry) => {
                const pkgChanges = () =>
                    packagesOnly()
                        ? entry.changes.filter((c) => c.purl != null)
                        : entry.changes;
                const visibleChanges = () => {
                    const f = typeFilter();
                    const q = nameFilter().toLowerCase().trim();
                    let changes = f ? pkgChanges().filter(c => classifyChange(c) === f) : pkgChanges();
                    if (q) {
                        changes = changes.filter(c =>
                            c.name.toLowerCase().includes(q) ||
                            (c.group?.toLowerCase().includes(q) ?? false) ||
                            (c.purl?.toLowerCase().includes(q) ?? false)
                        );
                    }
                    return changes;
                };
                const addedCount = () => pkgChanges().filter((c) => c.type === "added").length;
                const removedCount = () => pkgChanges().filter((c) => c.type === "removed").length;
                const upgradedCount = () => pkgChanges().filter((c) => classifyChange(c) === "upgraded").length;
                const downgradedCount = () => pkgChanges().filter((c) => classifyChange(c) === "downgraded").length;

                return (
                <Show when={visibleChanges().length > 0}>
                <div class="changelog-entry">
                    <div class="changelog-entry-header">
                        <div class="text-sm">
                            <A href={`/sboms/${entry.from.id}`} class="mono">
                                {changelogRefLabel(entry.from)}
                            </A>
                            {" → "}
                            <A href={`/sboms/${entry.to.id}`} class="mono">
                                {changelogRefLabel(entry.to)}
                            </A>
                            <span class="text-muted">
                                {" "}
                                (
                                {relativeDate(
                                    entry.to.buildDate ?? entry.to.createdAt,
                                )}
                                )
                            </span>
                        </div>
                        <div class="changelog-summary">
                            {(() => {
                                const kinds = [
                                    { key: "added",      count: addedCount(),      cls: "badge-success", label: (n: number) => `+${n} added` },
                                    { key: "removed",    count: removedCount(),    cls: "badge-danger",  label: (n: number) => `-${n} removed` },
                                    { key: "upgraded",   count: upgradedCount(),   cls: "badge-success", label: (n: number) => `↑${n} upgraded` },
                                    { key: "downgraded", count: downgradedCount(), cls: "badge-danger",  label: (n: number) => `↓${n} downgraded` },
                                ];
                                return kinds
                                    .filter(k => k.count > 0)
                                    .map(k => (
                                        <button
                                            class={`badge ${k.cls}`}
                                            style={{
                                                cursor: "pointer",
                                                border: "none",
                                                opacity: typeFilter() && typeFilter() !== k.key ? "0.45" : "1",
                                                "font-weight": typeFilter() === k.key ? "700" : undefined,
                                            }}
                                            onClick={() => toggleTypeFilter(k.key)}
                                            title={typeFilter() === k.key ? "Click to clear filter" : `Click to show only ${k.key}`}
                                        >
                                            {k.label(k.count)}
                                        </button>
                                    ));
                            })()}
                        </div>
                    </div>
                    <div class="table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>Change</th>
                                    <th>Component</th>
                                    <th>Version</th>
                                    <th>Package</th>
                                </tr>
                            </thead>
                            <tbody>
                                <For each={visibleChanges()}>
                                    {(change) => (
                                        <tr>
                                            <td>
                                                {(() => {
                                                    const kind = classifyChange(change);
                                                    const cls =
                                                        kind === "added" || kind === "upgraded"
                                                            ? "badge-success"
                                                            : kind === "removed" || kind === "downgraded"
                                                              ? "badge-danger"
                                                              : "badge-warning";
                                                    return <span class={`badge ${cls}`}>{kind}</span>;
                                                })()}
                                            </td>
                                            <td>
                                                {change.group
                                                    ? `${change.group}/`
                                                    : ""}
                                                {change.name}
                                            </td>
                                            <td class="mono">
                                                <Show
                                                    when={
                                                        change.previousVersion
                                                    }
                                                >
                                                    <span class="text-muted">
                                                        {change.previousVersion}
                                                    </span>
                                                    {" → "}
                                                </Show>
                                                {change.version ?? "—"}
                                            </td>
                                            <td class="mono truncate text-muted">
                                                {change.purl ?? "—"}
                                            </td>
                                        </tr>
                                    )}
                                </For>
                            </tbody>
                        </table>
                    </div>
                </div>
                </Show>
                );
            }}
        </For>
        </>
    );
}
