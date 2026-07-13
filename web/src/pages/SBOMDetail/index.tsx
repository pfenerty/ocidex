import "~/components/DetailSection.css";
import { Show, For, createSignal, createMemo } from "solid-js";
import { A, useParams, useNavigate } from "@solidjs/router";
import { useSBOM, useSBOMComponents, sbomComponents, useSBOMDependencies, useArtifactSBOMs } from "~/api/queries";
import { useArtifactNames } from "~/api/queries";
import type { OCIMetadata, Provenance, GitCommitMetadata } from "~/api/client";
import { Loading, ErrorBox, EmptyState } from "~/components/Feedback";
import CopyDigest from "~/components/CopyDigest";
import ImageMetadataCard from "~/components/ImageMetadataCard";
import ProvenanceCard from "~/components/ProvenanceCard";
import GitCommitCard from "~/components/GitCommitCard";
import SummaryBand, { type SbomTab } from "~/components/SummaryBand";
import { VulnSummaryBar } from "~/components/VulnBadge";
import { trustStatus, trustBadgeClass } from "~/utils/trust";
import { parsePurl } from "~/utils/purl";
import { artifactDisplayName, formatDateTime, plural } from "~/utils/format";
import { PackagesTab } from "./PackagesTab";

export default function SBOMDetail() {
    const params = useParams<{ id: string }>();
    const navigate = useNavigate();
    const [tab, setTab] = createSignal<SbomTab>("packages");

    const artifactLookup = useArtifactNames();
    const artifactLabel = (id: string | undefined) => {
        const a = artifactLookup(id);
        return a ? artifactDisplayName(a) : undefined;
    };

    const sbomQuery = useSBOM(() => params.id);
    const componentsQuery = useSBOMComponents(() => params.id);
    const loadedComponents = () => sbomComponents(componentsQuery.data?.pages);
    const depsQuery = useSBOMDependencies(() => params.id);

    const siblingsQuery = useArtifactSBOMs(
        () => sbomQuery.data?.artifactId ?? "",
        () => ({ limit: 50, subject_version: sbomQuery.data?.subjectVersion }),
        { enabled: () => sbomQuery.data?.artifactId !== undefined && sbomQuery.data.subjectVersion !== undefined },
    );

    const archSiblings = () => {
        const seen = new Set<string>();
        return (siblingsQuery.data?.data ?? []).filter(s => {
            if (s.architecture === undefined) return false;
            if (seen.has(s.architecture)) return false;
            seen.add(s.architecture);
            return true;
        });
    };

    const provenance = () => sbomQuery.data?.enrichments?.provenance as Provenance | undefined;
    const metadata = () => sbomQuery.data?.enrichments?.["oci-metadata"] as OCIMetadata | undefined;
    const gitCommit = () => sbomQuery.data?.enrichments?.git as GitCommitMetadata | undefined;

    // Top package ecosystems (purl types) for the Packages summary tile.
    const ecosystems = createMemo(() => {
        const counts = new Map<string, number>();
        for (const c of loadedComponents()) {
            if (c.type === "file") continue;
            const t = parsePurl(c.purl ?? "")?.type ?? c.type;
            if (t === "") continue;
            counts.set(t, (counts.get(t) ?? 0) + 1);
        }
        return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(e => e[0]);
    });

    const title = () => {
        const s = sbomQuery.data;
        if (!s) return params.id;
        const name = artifactLabel(s.artifactId);
        if (name !== undefined && s.subjectVersion !== undefined && s.subjectVersion !== "") return `${name} @ ${s.subjectVersion}`;
        if (name !== undefined) return name;
        if (s.subjectVersion !== undefined && s.subjectVersion !== "") return s.subjectVersion;
        return "SBOM Detail";
    };

    const subtitle = () => {
        const s = sbomQuery.data;
        if (!s) return "";
        const parts: string[] = [`CycloneDX ${s.specVersion}`];
        if (s.componentCount !== undefined) parts.push(plural(s.componentCount, "component"));
        parts.push(`Ingested ${formatDateTime(s.createdAt)}`);
        return parts.join(" · ");
    };

    return (
        <>
            <div class="breadcrumb">
                <A href="/sboms">SBOMs</A>
                <span class="separator">/</span>
                <Show when={sbomQuery.data?.artifactId} keyed>
                    {(artifactId) => (
                        <>
                            <A href={`/artifacts/${artifactId}`}>{artifactLabel(artifactId) ?? "Artifact"}</A>
                            <span class="separator">/</span>
                        </>
                    )}
                </Show>
                <span>{(sbomQuery.data?.subjectVersion ?? formatDateTime(sbomQuery.data?.createdAt ?? "")) || params.id}</span>
            </div>

            <Show when={!sbomQuery.isLoading} fallback={<Loading />}>
                <Show
                    when={!sbomQuery.isError && sbomQuery.data !== undefined ? sbomQuery.data : undefined}
                    keyed
                    fallback={<ErrorBox error={sbomQuery.error} />}
                >
                    {(s) => (
                        <>
                            {/* --- Hero --- */}
                            <div class="page-header">
                                <div class="page-header-row">
                                    <div>
                                        <h2 style={{ display: "flex", "align-items": "center", gap: "0.6rem", "flex-wrap": "wrap" }}>
                                            {title()}
                                            <Show when={trustStatus(provenance())}>
                                                {(t) => <span class={trustBadgeClass(t().variant)}>{t().label}</span>}
                                            </Show>
                                        </h2>
                                        <p class="text-muted">{subtitle()}</p>
                                        <Show when={s.digest} keyed>
                                            {(digest) => (
                                                <CopyDigest
                                                    digest={digest}
                                                    artifactName={artifactLookup(s.artifactId)?.name}
                                                    class="text-sm"
                                                />
                                            )}
                                        </Show>
                                    </div>
                                    <div class="btn-group">
                                        <Show when={s.artifactId}>
                                            <A href={`/artifacts/${s.artifactId}`} class="btn btn-sm">View Artifact</A>
                                        </Show>
                                        <Show when={s.artifactId !== undefined && s.subjectVersion !== undefined}>
                                            <A href={`/artifacts/${s.artifactId}/versions/${encodeURIComponent(s.subjectVersion ?? "")}`} class="btn btn-sm">
                                                View build history
                                            </A>
                                        </Show>
                                        <A href={`/diff?from=${s.id}&to=${s.id}`} class="btn btn-sm">Compare</A>
                                    </div>
                                </div>
                            </div>

                            {/* --- Arch switcher --- */}
                            <Show when={archSiblings().length > 1}>
                                <div class="tab-bar mb-sm">
                                    <For each={archSiblings()}>
                                        {(sibling) => (
                                            <button
                                                class={sibling.id === params.id ? "active" : ""}
                                                onClick={() => navigate(`/sboms/${sibling.id}`)}
                                            >
                                                {sibling.architecture}
                                            </button>
                                        )}
                                    </For>
                                </div>
                            </Show>

                            {/* --- Summary band --- */}
                            <SummaryBand
                                provenance={provenance()}
                                metadata={metadata()}
                                git={gitCommit()}
                                packageCount={s.packageCount}
                                ecosystems={ecosystems()}
                                specVersion={s.specVersion}
                                ingestedAt={s.createdAt}
                                active={tab()}
                                onSelect={setTab}
                            />

                            {/* --- Vulnerability summary --- */}
                            <VulnSummaryBar summary={s.vulnSummary} />

                            {/* --- Tabs --- */}
                            <div class="tab-bar">
                                <button class={tab() === "packages" ? "active" : ""} onClick={() => setTab("packages")}>
                                    Packages ({s.packageCount})
                                </button>
                                <button class={tab() === "provenance" ? "active" : ""} onClick={() => setTab("provenance")}>Provenance</button>
                                <button class={tab() === "image" ? "active" : ""} onClick={() => setTab("image")}>Image</button>
                                <button class={tab() === "git" ? "active" : ""} onClick={() => setTab("git")}>Git</button>
                                <button class={tab() === "raw" ? "active" : ""} onClick={() => setTab("raw")}>Raw</button>
                            </div>

                            {/* --- Packages tab --- */}
                            <Show when={tab() === "packages"}>
                                <Show when={!componentsQuery.isLoading} fallback={<Loading />}>
                                    <Show
                                        when={!componentsQuery.isError}
                                        fallback={<ErrorBox error={componentsQuery.error} />}
                                    >
                                        <PackagesTab
                                            components={loadedComponents()}
                                            depsGraph={(depsQuery.data?.edges.length ?? 0) > 0 ? depsQuery.data : undefined}
                                            hasMore={componentsQuery.hasNextPage}
                                            loadingMore={componentsQuery.isFetchingNextPage}
                                            onLoadMore={() => void componentsQuery.fetchNextPage()}
                                        />
                                    </Show>
                                </Show>
                            </Show>

                            {/* --- Provenance tab --- */}
                            <Show when={tab() === "provenance"}>
                                <Show
                                    when={provenance()}
                                    keyed
                                    fallback={<EmptyState title="No provenance data" message="No cosign signature or SLSA attestation was found for this image. Provenance enrichment runs after ingestion." />}
                                >
                                    {(prov) => <ProvenanceCard provenance={prov} />}
                                </Show>
                            </Show>

                            {/* --- Image tab --- */}
                            <Show when={tab() === "image"}>
                                <Show
                                    when={metadata()}
                                    keyed
                                    fallback={<EmptyState title="No image metadata" message="No OCI image metadata enrichment is available for this SBOM yet." />}
                                >
                                    {(m) => <ImageMetadataCard metadata={m} ingestedAt={s.createdAt} />}
                                </Show>
                            </Show>

                            {/* --- Git tab --- */}
                            <Show when={tab() === "git"}>
                                <Show
                                    when={gitCommit()?.resolved === true ? gitCommit() : undefined}
                                    fallback={
                                        <EmptyState
                                            title="No git commit data"
                                            message={
                                                gitCommit()?.reason !== undefined && gitCommit()?.reason !== ""
                                                    ? `Git enrichment could not resolve a commit: ${gitCommit()?.reason}.`
                                                    : "No git commit enrichment is available for this SBOM yet."
                                            }
                                        />
                                    }
                                >
                                    {(commit) => <GitCommitCard commit={commit()} />}
                                </Show>
                            </Show>

                            {/* --- Raw tab (identity + CycloneDX internals) --- */}
                            <Show when={tab() === "raw"}>
                                <div class="card mb-4">
                                    <div class="card-header"><h3>SBOM details</h3></div>
                                    <div class="detail-grid">
                                        <Show when={s.artifactId}>
                                            <div class="detail-field">
                                                <span class="detail-label">Artifact</span>
                                                <span class="detail-value">
                                                    <A href={`/artifacts/${s.artifactId}`}>{artifactLabel(s.artifactId) ?? s.artifactId}</A>
                                                </span>
                                            </div>
                                        </Show>
                                        <Show when={s.subjectVersion}>
                                            <div class="detail-field">
                                                <span class="detail-label">Version</span>
                                                <span class="detail-value">{s.subjectVersion}</span>
                                            </div>
                                        </Show>
                                        <div class="detail-field">
                                            <span class="detail-label">Spec Version</span>
                                            <span class="detail-value">CycloneDX {s.specVersion}</span>
                                        </div>
                                        <div class="detail-field">
                                            <span class="detail-label">BOM Version</span>
                                            <span class="detail-value">{s.version}</span>
                                        </div>
                                        <Show when={s.serialNumber}>
                                            <div class="detail-field">
                                                <span class="detail-label">Serial Number</span>
                                                <span class="detail-value font-mono text-sm">{s.serialNumber}</span>
                                            </div>
                                        </Show>
                                        <div class="detail-field">
                                            <span class="detail-label">Internal ID</span>
                                            <span class="detail-value font-mono text-sm">{s.id}</span>
                                        </div>
                                        <div class="detail-field">
                                            <span class="detail-label">Ingested</span>
                                            <span class="detail-value">{formatDateTime(s.createdAt)}</span>
                                        </div>
                                        <Show when={s.digest} keyed>
                                            {(digest) => (
                                                <div class="detail-field">
                                                    <span class="detail-label">Image Digest</span>
                                                    <CopyDigest digest={digest} artifactName={artifactLookup(s.artifactId)?.name} full class="detail-value" />
                                                </div>
                                            )}
                                        </Show>
                                    </div>
                                </div>
                            </Show>
                        </>
                    )}
                </Show>
            </Show>
        </>
    );
}
