import { createSignal, createMemo, Show, For } from "solid-js";
import { A, useParams, useNavigate } from "@solidjs/router";
import { useSBOM, useSBOMComponents, useSBOMDependencies, useArtifactSBOMs } from "~/api/queries";
import { useArtifactNames } from "~/api/queries";
import type {
    OCIMetadata,
    ComponentSummary,
    DependencyEdge,
} from "~/api/client";
import { Loading, ErrorBox, EmptyState } from "~/components/Feedback";
import ImageMetadataCard from "~/components/ImageMetadataCard";
import PurlLink from "~/components/PurlLink";
import {
    artifactDisplayName,
    formatDateTime,
    shortDigest,
    plural,
} from "~/utils/format";
import { parsePurl } from "~/utils/purl";

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
        { enabled: () => !!(sbomQuery.data?.artifactId && sbomQuery.data?.subjectVersion) },
    );

    const archSiblings = () => (siblingsQuery.data?.data ?? []).filter(s => s.architecture != null);

    const title = () => {
        const s = sbomQuery.data;
        if (!s) return params.id;
        const name = artifactLabel(s.artifactId);
        if (name && s.subjectVersion) return `${name} @ ${s.subjectVersion}`;
        if (name) return name;
        if (s.subjectVersion) return s.subjectVersion;
        return "SBOM Detail";
    };

    const subtitle = () => {
        const s = sbomQuery.data;
        if (!s) return "";
        const parts: string[] = [];
        parts.push(`CycloneDX ${s.specVersion}`);
        if (s.componentCount != null) {
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
                <Show when={sbomQuery.data?.artifactId}>
                    <A href={`/artifacts/${sbomQuery.data!.artifactId}`}>
                        {artifactLabel(sbomQuery.data!.artifactId) ??
                            "Artifact"}
                    </A>
                    <span class="separator">/</span>
                </Show>
                <span>
                    {(sbomQuery.data?.subjectVersion ??
                        formatDateTime(sbomQuery.data?.createdAt ?? "")) ||
                        params.id}
                </span>
            </div>

            <Show when={!sbomQuery.isLoading} fallback={<Loading />}>
                <Show
                    when={!sbomQuery.isError}
                    fallback={<ErrorBox error={sbomQuery.error} />}
                >
                    {(() => {
                        const s = sbomQuery.data!;
                        return (
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
                                                        s.componentCount!,
                                                        "component",
                                                    )}
                                                </span>
                                            </div>
                                        </Show>
                                        <Show when={s.digest}>
                                            <div class="detail-field">
                                                <span class="detail-label">
                                                    Image Digest
                                                </span>
                                                <span
                                                    class="detail-value mono"
                                                    title={s.digest}
                                                >
                                                    {shortDigest(s.digest!)}
                                                </span>
                                            </div>
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
                                        <Show when={s.digest}>
                                            <div class="detail-field">
                                                <span class="detail-label">
                                                    Full Digest
                                                </span>
                                                <span class="detail-value mono text-sm">
                                                    {s.digest}
                                                </span>
                                            </div>
                                        </Show>
                                    </div>
                                </details>

                                {/* --- OCI Image Metadata (from enrichment) --- */}
                                <Show when={s.enrichments?.["oci-metadata"]}>
                                    <ImageMetadataCard
                                        metadata={
                                            s.enrichments![
                                                "oci-metadata"
                                            ] as OCIMetadata
                                        }
                                        ingestedAt={s.createdAt}
                                    />
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
                                        <Show when={s.componentCount != null}>
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
                                            when={!componentsQuery.isError}
                                            fallback={
                                                <ErrorBox
                                                    error={
                                                        componentsQuery.error
                                                    }
                                                />
                                            }
                                        >
                                            <PackagesTab
                                                components={
                                                    componentsQuery.data!
                                                        .components
                                                }
                                            />
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
                                                    depsQuery.data &&
                                                    depsQuery.data.edges
                                                        .length > 0
                                                }
                                                fallback={
                                                    <EmptyState
                                                        title="No dependency relationships"
                                                        message="This SBOM does not contain dependency relationship data."
                                                    />
                                                }
                                            >
                                                <DependencyTreeView
                                                    graph={depsQuery.data!}
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

/* ------------------------------------------------------------------ */
/*  Packages Tab                                                       */
/* ------------------------------------------------------------------ */

function PackagesTab(props: { components: ComponentSummary[] }) {
    const [filter, setFilter] = createSignal("");
    const [typeFilter, setTypeFilter] = createSignal("all");
    const [page, setPage] = createSignal(0);
    const pageSize = 50;

    const ecoType = (c: ComponentSummary) =>
        (c.purl && parsePurl(c.purl)?.type) || c.type;

    // Exclude "file" type components from the entire view
    const packages = createMemo(() =>
        props.components.filter((c) => c.type !== "file"),
    );

    const types = createMemo(() => {
        const set = new Set(packages().map(ecoType));
        return Array.from(set).sort();
    });

    const filtered = createMemo(() => {
        const comps = packages();
        if (comps.length === 0) return [];
        const q = filter().toLowerCase();
        const t = typeFilter();
        return comps.filter((c) => {
            if (t !== "all" && ecoType(c) !== t) return false;
            if (!q) return true;
            const display =
                (c.group ? `${c.group  }/` : "") +
                c.name +
                (c.version ? `@${  c.version}` : "");
            return (
                display.toLowerCase().includes(q) ||
                (c.purl?.toLowerCase().includes(q) ?? false)
            );
        });
    });

    const pageCount = () =>
        Math.max(1, Math.ceil(filtered().length / pageSize));
    const paged = () =>
        filtered().slice(page() * pageSize, (page() + 1) * pageSize);

    // Reset page when filter changes
    const updateFilter = (v: string) => {
        setFilter(v);
        setPage(0);
    };
    const updateType = (v: string) => {
        setTypeFilter(v);
        setPage(0);
    };

    return (
        <Show
            when={packages().length > 0}
            fallback={
                <EmptyState
                    title="No packages"
                    message="This SBOM has no components."
                />
            }
        >
            <div class="card">
                <div class="search-bar mb-md" style={{ "flex-wrap": "wrap" }}>
                    <input
                        type="text"
                        placeholder="Filter packages…"
                        value={filter()}
                        onInput={(e) => updateFilter(e.currentTarget.value)}
                        style={{ flex: "1", "min-width": "200px" }}
                    />
                    <select
                        value={typeFilter()}
                        onChange={(e) => updateType(e.currentTarget.value)}
                    >
                        <option value="all">
                            All types ({packages().length})
                        </option>
                        <For each={types()}>
                            {(t) => <option value={t}>{t}</option>}
                        </For>
                    </select>
                    <span class="text-muted text-sm">
                        {filtered().length === packages().length
                            ? plural(filtered().length, "package")
                            : `${filtered().length} of ${packages().length} packages`}
                    </span>
                </div>

                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Version</th>
                                <th>Type</th>
                                <th>Package URL</th>
                                <th />
                            </tr>
                        </thead>
                        <tbody>
                            <For each={paged()}>
                                {(c) => (
                                    <tr>
                                        <td>
                                            <A href={`/components/${c.id}`}>
                                                {c.group ? `${c.group}/` : ""}
                                                {c.name}
                                            </A>
                                        </td>
                                        <td class="mono">
                                            {c.version ?? (
                                                <span class="text-muted">
                                                    —
                                                </span>
                                            )}
                                        </td>
                                        <td>
                                            <span class="badge">
                                                {(c.purl &&
                                                    parsePurl(c.purl)?.type) ||
                                                    c.type}
                                            </span>
                                        </td>
                                        <td class="truncate">
                                            <Show
                                                when={c.purl}
                                                fallback={
                                                    <span class="text-muted">
                                                        —
                                                    </span>
                                                }
                                            >
                                                <PurlLink
                                                    purl={c.purl!}
                                                    showBadge
                                                />
                                            </Show>
                                        </td>
                                        <td>
                                            <A
                                                href={`/components/${c.id}`}
                                                class="text-sm"
                                            >
                                                Details →
                                            </A>
                                        </td>
                                    </tr>
                                )}
                            </For>
                        </tbody>
                    </table>
                </div>

                <Show when={pageCount() > 1}>
                    <div class="pagination">
                        <span>
                            Page {page() + 1} of {pageCount()}
                        </span>
                        <div class="pagination-controls">
                            <button
                                disabled={page() === 0}
                                onClick={() => setPage(page() - 1)}
                            >
                                ← Prev
                            </button>
                            <button
                                disabled={page() >= pageCount() - 1}
                                onClick={() => setPage(page() + 1)}
                            >
                                Next →
                            </button>
                        </div>
                    </div>
                </Show>
            </div>
        </Show>
    );
}

/* ------------------------------------------------------------------ */
/*  Dependencies Tab – expandable tree                                 */
/* ------------------------------------------------------------------ */

interface TreeNode {
    ref: string;
    label: string;
    id?: string;
    purl?: string;
    children: string[];
}

function DependencyTreeView(props: {
    graph: { edges: DependencyEdge[]; nodes: ComponentSummary[] };
}) {
    // Build adjacency list and name map
    const treeData = createMemo(() => {
        const adj = new Map<string, string[]>();
        const allTargets = new Set<string>();

        for (const edge of props.graph.edges) {
            if (!adj.has(edge.from)) adj.set(edge.from, []);
            adj.get(edge.from)!.push(edge.to);
            allTargets.add(edge.to);
        }

        // Name lookup: ref -> display label & component id
        const nameMap = new Map<
            string,
            { label: string; id?: string; purl?: string }
        >();
        for (const node of props.graph.nodes) {
            const label = node.group ? `${node.group}/${node.name}` : node.name;
            const display = node.version ? `${label}@${node.version}` : label;
            const info = { label: display, id: node.id, purl: node.purl };
            nameMap.set(node.id, info);
            nameMap.set(node.name, info);
            if (node.purl) nameMap.set(node.purl, info);
            if (node.bomRef) nameMap.set(node.bomRef, info);
        }

        // Find root nodes
        const fromRefs = [...adj.keys()];
        let rootRefs = fromRefs.filter((r) => !allTargets.has(r));
        if (rootRefs.length === 0) rootRefs = fromRefs.slice(0, 10);

        // Build TreeNode map for all refs
        const allRefs = new Set([...adj.keys(), ...allTargets]);
        const nodes = new Map<string, TreeNode>();
        for (const ref of allRefs) {
            const info = nameMap.get(ref);
            nodes.set(ref, {
                ref,
                label: info?.label ?? ref,
                id: info?.id,
                purl: info?.purl,
                children: adj.get(ref) ?? [],
            });
        }

        return {
            roots: rootRefs,
            nodes,
            edgeCount: props.graph.edges.length,
            nodeCount: props.graph.nodes.length,
        };
    });

    return (
        <div class="card">
            <div class="card-header">
                <span class="text-sm text-muted">
                    {plural(treeData().nodeCount, "component")},{" "}
                    {plural(treeData().edgeCount, "dependency edge")}
                </span>
            </div>
            <div
                style={{
                    "max-height": "600px",
                    "overflow-y": "auto",
                    padding: "0.5rem 0",
                }}
            >
                <For each={treeData().roots}>
                    {(rootRef) => {
                        const node = treeData().nodes.get(rootRef);
                        return node ? (
                            <TreeNodeRow
                                node={node}
                                allNodes={treeData().nodes}
                                depth={0}
                                visited={new Set()}
                            />
                        ) : null;
                    }}
                </For>
            </div>
        </div>
    );
}

function TreeNodeRow(props: {
    node: TreeNode;
    allNodes: Map<string, TreeNode>;
    depth: number;
    visited: Set<string>;
}) {
    const [expanded, setExpanded] = createSignal(props.depth === 0);
    const hasChildren = () => props.node.children.length > 0;
    const isCyclic = () => props.visited.has(props.node.ref);

    const childNodes = createMemo(() => {
        if (!expanded() || isCyclic()) return [];
        return props.node.children
            .map((ref) => props.allNodes.get(ref))
            .filter((n): n is TreeNode => !!n);
    });

    const nextVisited = createMemo(() => {
        const s = new Set(props.visited);
        s.add(props.node.ref);
        return s;
    });

    return (
        <>
            <div
                class="dep-tree-row"
                style={{
                    "padding-left": `${props.depth * 1.25 + 0.75}rem`,
                    display: "flex",
                    "align-items": "center",
                    gap: "0.375rem",
                    padding: `0.3rem 0.75rem 0.3rem ${props.depth * 1.25 + 0.75}rem`,
                    "font-size": "0.85rem",
                    "border-bottom": "1px solid var(--color-border)",
                    cursor: hasChildren() ? "pointer" : "default",
                }}
                onClick={() => hasChildren() && setExpanded(!expanded())}
            >
                {/* Toggle icon */}
                <span
                    style={{
                        width: "1rem",
                        "text-align": "center",
                        color: "var(--color-text-dim)",
                        "font-size": "0.7rem",
                        "flex-shrink": "0",
                        transition: "transform 0.15s",
                        transform:
                            hasChildren() && expanded()
                                ? "rotate(90deg)"
                                : "rotate(0deg)",
                    }}
                >
                    {hasChildren() ? "▸" : " "}
                </span>

                {/* Label */}
                <Show
                    when={props.node.id}
                    fallback={
                        <span
                            class="mono"
                            style={{ color: "var(--color-text-muted)" }}
                        >
                            {props.node.label}
                        </span>
                    }
                >
                    <A
                        href={`/components/${props.node.id}`}
                        class="mono"
                        style={{ "font-size": "0.85rem" }}
                        onClick={(e: Event) => e.stopPropagation()}
                    >
                        {props.node.label}
                    </A>
                </Show>

                {/* Dep count badge */}
                <Show when={hasChildren()}>
                    <span
                        class="badge badge-sm"
                        style={{ "margin-left": "0.25rem" }}
                    >
                        {props.node.children.length}
                    </span>
                </Show>

                {/* Cycle indicator */}
                <Show when={isCyclic()}>
                    <span
                        class="badge badge-warning"
                        style={{
                            "font-size": "0.65rem",
                            "margin-left": "0.25rem",
                        }}
                    >
                        circular
                    </span>
                </Show>
            </div>

            {/* Render children */}
            <Show when={expanded() && !isCyclic()}>
                <For each={childNodes()}>
                    {(child) => (
                        <TreeNodeRow
                            node={child}
                            allNodes={props.allNodes}
                            depth={props.depth + 1}
                            visited={nextVisited()}
                        />
                    )}
                </For>
            </Show>
        </>
    );
}
