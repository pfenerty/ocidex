import { createSignal, Show, For } from "solid-js";
import { A, useParams, useNavigate } from "@solidjs/router";
import { useSBOM, useSBOMComponents, useSBOMDependencies, useArtifactSBOMs } from "~/api/queries";
import { useArtifactNames } from "~/api/queries";
import type { OCIMetadata } from "~/api/client";
import { Loading, ErrorBox, EmptyState } from "~/components/Feedback";
import CopyDigest from "~/components/CopyDigest";
import ImageMetadataCard from "~/components/ImageMetadataCard";
import {
    artifactDisplayName,
    formatDateTime,
    plural,
} from "~/utils/format";
import { PackagesTab, DependencyTreeView } from "./PackagesTab";

export default function SBOMDetail() {
    const params = useParams<{ id: string }>();
    const [tab, setTab] = createSignal<"packages" | "dependencies">("packages");

    const artifactLookup = useArtifactNames();
    const artifactLabel = (id: string | undefined) => {
        const a = artifactLookup(id);
        return a ? artifactDisplayName(a) : undefined;
    };

    const sbomQuery = useSBOM(() => params.id);

    const componentsQuery = useSBOMComponents(() => params.id);

    const depsQuery = useSBOMDependencies(() => params.id, {
        enabled: () => tab() === "dependencies",
    });

    const navigate = useNavigate();

    const siblingsQuery = useArtifactSBOMs(
        () => sbomQuery.data?.artifactId ?? "",
        () => ({ limit: 50, subject_version: sbomQuery.data?.subjectVersion }),
        { enabled: () => sbomQuery.data?.artifactId !== undefined && sbomQuery.data.subjectVersion !== undefined },
    );

    const archSiblings = () => (siblingsQuery.data?.data ?? []).filter(s => s.architecture !== undefined);

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
        const parts: string[] = [];
        parts.push(`CycloneDX ${s.specVersion}`);
        if (s.componentCount !== undefined) {
            parts.push(plural(s.componentCount, "component"));
        }
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
                            <A href={`/artifacts/${artifactId}`}>
                                {artifactLabel(artifactId) ?? "Artifact"}
                            </A>
                            <span class="separator">/</span>
                        </>
                    )}
                </Show>
                <span>
                    {(sbomQuery.data?.subjectVersion ??
                        formatDateTime(sbomQuery.data?.createdAt ?? "")) ||
                        params.id}
                </span>
            </div>

            <Show when={!sbomQuery.isLoading} fallback={<Loading />}>
                <Show
                    when={!sbomQuery.isError && sbomQuery.data !== undefined ? sbomQuery.data : undefined}
                    keyed
                    fallback={<ErrorBox error={sbomQuery.error} />}
                >
                    {(s) => (
                            <>
                                <div class="page-header">
                                    <div class="page-header-row">
                                        <div>
                                            <h2>{title()}</h2>
                                            <p class="text-muted">
                                                {subtitle()}
                                            </p>
                                        </div>
                                        <div class="btn-group">
                                            <Show when={s.artifactId}>
                                                <A
                                                    href={`/artifacts/${s.artifactId}`}
                                                    class="btn btn-sm"
                                                >
                                                    View Artifact
                                                </A>
                                            </Show>
                                            <A
                                                href={`/diff?from=${s.id}&to=${s.id}`}
                                                class="btn btn-sm"
                                            >
                                                Compare
                                            </A>
                                        </div>
                                    </div>
                                </div>

                                {/* --- About this SBOM --- */}
                                <div class="card mb-md">
                                    <div class="card-header">
                                        <h3>About this SBOM</h3>
                                    </div>
                                    <div class="detail-grid">
                                        <Show when={s.artifactId}>
                                            <div class="detail-field">
                                                <span class="detail-label">
                                                    Artifact
                                                </span>
                                                <span class="detail-value">
                                                    <A
                                                        href={`/artifacts/${s.artifactId}`}
                                                    >
                                                        {artifactLabel(
                                                            s.artifactId,
                                                        ) ?? s.artifactId}
                                                    </A>
                                                </span>
                                            </div>
                                        </Show>
                                        <Show when={s.subjectVersion}>
                                            <div class="detail-field">
                                                <span class="detail-label">
                                                    Version
                                                </span>
                                                <span class="detail-value">
                                                    {s.subjectVersion}
                                                </span>
                                            </div>
                                        </Show>
                                        <Show
                                            when={
                                                s.componentCount !== undefined
                                            }
                                        >
                                            <div class="detail-field">
                                                <span class="detail-label">
                                                    Components
                                                </span>
                                                <span class="detail-value">
                                                    {plural(
                                                        s.componentCount ?? 0,
                                                        "component",
                                                    )}
                                                </span>
                                            </div>
                                        </Show>
                                        <Show when={s.digest} keyed>
                                            {(digest) => (
                                                <div class="detail-field">
                                                    <span class="detail-label">
                                                        Image Digest
                                                    </span>
                                                    <CopyDigest
                                                        digest={digest}
                                                        artifactName={artifactLookup(s.artifactId)?.name}
                                                        class="detail-value"
                                                    />
                                                </div>
                                            )}
                                        </Show>
                                        <div class="detail-field">
                                            <span class="detail-label">
                                                Ingested
                                            </span>
                                            <span class="detail-value">
                                                {formatDateTime(s.createdAt)}
                                            </span>
                                        </div>
                                    </div>
                                </div>

                                {/* --- CycloneDX Metadata (collapsed details) --- */}
                                <details class="card mb-md">
                                    <summary class="card-header card-summary">
                                        <h3>CycloneDX Metadata</h3>
                                        <span class="badge">
                                            {s.specVersion}
                                        </span>
                                    </summary>
                                    <div class="detail-grid">
                                        <div class="detail-field">
                                            <span class="detail-label">
                                                Spec Version
                                            </span>
                                            <span class="detail-value">
                                                {s.specVersion}
                                            </span>
                                        </div>
                                        <div class="detail-field">
                                            <span class="detail-label">
                                                BOM Version
                                            </span>
                                            <span class="detail-value">
                                                {s.version}
                                            </span>
                                        </div>
                                        <Show when={s.serialNumber}>
                                            <div class="detail-field">
                                                <span class="detail-label">
                                                    Serial Number
                                                </span>
                                                <span class="detail-value mono text-sm">
                                                    {s.serialNumber}
                                                </span>
                                            </div>
                                        </Show>
                                        <div class="detail-field">
                                            <span class="detail-label">
                                                Internal ID
                                            </span>
                                            <span class="detail-value mono text-sm">
                                                {s.id}
                                            </span>
                                        </div>
                                        <Show when={s.digest} keyed>
                                            {(digest) => (
                                                <div class="detail-field">
                                                    <span class="detail-label">
                                                        Full Digest
                                                    </span>
                                                    <CopyDigest
                                                        digest={digest}
                                                        artifactName={artifactLookup(s.artifactId)?.name}
                                                        full
                                                        class="detail-value"
                                                    />
                                                </div>
                                            )}
                                        </Show>
                                    </div>
                                </details>

                                {/* --- OCI Image Metadata (from enrichment) --- */}
                                <Show when={s.enrichments?.["oci-metadata"] as OCIMetadata | undefined} keyed>
                                    {(metadata) => (
                                        <ImageMetadataCard
                                            metadata={metadata}
                                            ingestedAt={s.createdAt}
                                        />
                                    )}
                                </Show>

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

                                {/* --- Tab bar --- */}
                                <div class="tab-bar">
                                    <button
                                        class={
                                            tab() === "packages" ? "active" : ""
                                        }
                                        onClick={() => setTab("packages")}
                                    >
                                        Packages
                                        <Show when={s.componentCount !== undefined}>
                                            {" "}
                                            ({s.componentCount})
                                        </Show>
                                    </button>
                                    <button
                                        class={
                                            tab() === "dependencies"
                                                ? "active"
                                                : ""
                                        }
                                        onClick={() => setTab("dependencies")}
                                    >
                                        Dependency Tree
                                    </button>
                                </div>

                                <Show when={tab() === "packages"}>
                                    <Show
                                        when={!componentsQuery.isLoading}
                                        fallback={<Loading />}
                                    >
                                        <Show
                                            when={!componentsQuery.isError && componentsQuery.data !== undefined ? componentsQuery.data : undefined}
                                            keyed
                                            fallback={
                                                <ErrorBox
                                                    error={
                                                        componentsQuery.error
                                                    }
                                                />
                                            }
                                        >
                                            {(data) => (
                                                <PackagesTab
                                                    components={data.components}
                                                />
                                            )}
                                        </Show>
                                    </Show>
                                </Show>

                                <Show when={tab() === "dependencies"}>
                                    <Show
                                        when={!depsQuery.isLoading}
                                        fallback={<Loading />}
                                    >
                                        <Show
                                            when={!depsQuery.isError}
                                            fallback={
                                                <ErrorBox
                                                    error={depsQuery.error}
                                                />
                                            }
                                        >
                                            <Show
                                                when={
                                                    depsQuery.data !== undefined &&
                                                    depsQuery.data.edges.length > 0
                                                        ? depsQuery.data
                                                        : undefined
                                                }
                                                keyed
                                                fallback={
                                                    <EmptyState
                                                        title="No dependency relationships"
                                                        message="This SBOM does not contain dependency relationship data."
                                                    />
                                                }
                                            >
                                                {(graph) => (
                                                    <DependencyTreeView
                                                        graph={graph}
                                                    />
                                                )}
                                            </Show>
                                        </Show>
                                    </Show>
                                </Show>
                            </>
                    )}
                </Show>
            </Show>
        </>
    );
}
