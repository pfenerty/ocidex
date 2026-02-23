import { createSignal, Show, For } from "solid-js";
import { A, useParams } from "@solidjs/router";
import { useComponent, useComponentVersions } from "~/api/queries";
import type { ComponentVersionEntry } from "~/api/client";
import { Loading, ErrorBox, EmptyState } from "~/components/Feedback";
import PurlLink from "~/components/PurlLink";
import { purlToRegistryUrl, purlTypeLabel } from "~/utils/purl";
import {
    relativeDate,
    formatDateTime,
    shortDigest,
    plural,
} from "~/utils/format";

export default function ComponentDetail() {
    const params = useParams<{ id: string }>();

    const query = useComponent(() => params.id);

    const versionsQuery = useComponentVersions(
        () =>
            query.data
                ? {
                      name: query.data.name,
                      group: query.data.group || undefined,
                      version: query.data.version || undefined,
                      type: query.data.type || undefined,
                  }
                : undefined,
        { enabled: () => !!query.data?.name },
    );

    return (
        <>
            <div class="breadcrumb">
                <A href="/components">Components</A>
                <span class="separator">/</span>
                <span>{query.data?.name ?? params.id}</span>
            </div>

            <Show when={!query.isLoading} fallback={<Loading />}>
                <Show
                    when={!query.isError}
                    fallback={<ErrorBox error={query.error} />}
                >
                    {(() => {
                        const c = query.data!;
                        const licenses = () => c.licenses ?? [];
                        const hashes = () => c.hashes ?? [];
                        const externalRefs = () => c.externalReferences ?? [];

                        return (
                            <>
                                <div class="page-header">
                                    <div class="page-header-row">
                                        <div>
                                            <h2>
                                                {c.group ? `${c.group}/` : ""}
                                                {c.name}
                                            </h2>
                                            <p>
                                                <span class="badge">
                                                    {c.type}
                                                </span>
                                                <Show when={c.version}>
                                                    {" "}
                                                    {c.version}
                                                </Show>
                                            </p>
                                        </div>
                                        <div class="btn-group">
                                            <Show
                                                when={
                                                    c.purl &&
                                                    purlToRegistryUrl(c.purl)
                                                }
                                            >
                                                <a
                                                    href={
                                                        purlToRegistryUrl(
                                                            c.purl!,
                                                        )!
                                                    }
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    class="btn btn-sm btn-primary"
                                                >
                                                    View on{" "}
                                                    {purlTypeLabel(c.purl!) ??
                                                        "Registry"}
                                                </a>
                                            </Show>
                                        </div>
                                    </div>
                                </div>

                                <div class="detail-grid">
                                    <div class="detail-field">
                                        <span class="detail-label">Type</span>
                                        <span class="detail-value">
                                            {c.type}
                                        </span>
                                    </div>
                                    <Show when={c.group}>
                                        <div class="detail-field">
                                            <span class="detail-label">
                                                Group
                                            </span>
                                            <span class="detail-value">
                                                {c.group}
                                            </span>
                                        </div>
                                    </Show>
                                    <Show when={c.version}>
                                        <div class="detail-field">
                                            <span class="detail-label">
                                                Version
                                            </span>
                                            <span class="detail-value mono">
                                                {c.version}
                                            </span>
                                        </div>
                                    </Show>
                                    <Show when={c.purl}>
                                        <div class="detail-field">
                                            <span class="detail-label">
                                                PURL
                                            </span>
                                            <span class="detail-value">
                                                <PurlLink
                                                    purl={c.purl!}
                                                    showBadge
                                                />
                                            </span>
                                        </div>
                                    </Show>
                                    <Show when={c.cpe}>
                                        <div class="detail-field">
                                            <span class="detail-label">
                                                CPE
                                            </span>
                                            <span class="detail-value mono">
                                                {c.cpe}
                                            </span>
                                        </div>
                                    </Show>
                                    <Show when={c.scope}>
                                        <div class="detail-field">
                                            <span class="detail-label">
                                                Scope
                                            </span>
                                            <span class="detail-value">
                                                {c.scope}
                                            </span>
                                        </div>
                                    </Show>
                                    <Show when={c.publisher}>
                                        <div class="detail-field">
                                            <span class="detail-label">
                                                Publisher
                                            </span>
                                            <span class="detail-value">
                                                {c.publisher}
                                            </span>
                                        </div>
                                    </Show>
                                    <Show when={c.copyright}>
                                        <div class="detail-field">
                                            <span class="detail-label">
                                                Copyright
                                            </span>
                                            <span class="detail-value">
                                                {c.copyright}
                                            </span>
                                        </div>
                                    </Show>
                                </div>

                                <Show when={c.description}>
                                    <div class="card mb-md">
                                        <div class="card-header">
                                            <h3>Description</h3>
                                        </div>
                                        <p class="text-sm">{c.description}</p>
                                    </div>
                                </Show>

                                <div class="card mb-md">
                                    <div class="card-header">
                                        <h3>Found in SBOMs</h3>
                                        <Show when={versionsQuery.data}>
                                            <span class="badge">
                                                {plural(
                                                    (
                                                        versionsQuery.data!
                                                            .versions ?? []
                                                    ).length,
                                                    "SBOM",
                                                )}
                                            </span>
                                        </Show>
                                    </div>
                                    <Show
                                        when={!versionsQuery.isLoading}
                                        fallback={<Loading />}
                                    >
                                        <Show
                                            when={!versionsQuery.isError}
                                            fallback={
                                                <ErrorBox
                                                    error={versionsQuery.error}
                                                />
                                            }
                                        >
                                            <Show
                                                when={
                                                    versionsQuery.data &&
                                                    (
                                                        versionsQuery.data
                                                            .versions ?? []
                                                    ).length > 0
                                                }
                                                fallback={
                                                    <EmptyState
                                                        title="No SBOMs found"
                                                        message="This component does not appear in any indexed SBOMs."
                                                    />
                                                }
                                            >
                                                {(() => {
                                                    const versions = () => versionsQuery.data!.versions ?? [];
                                                    const hasArch = () => versions().some(v => v.architecture != null);
                                                    const groups = () => {
                                                        if (!hasArch()) return null;
                                                        const order: string[] = [];
                                                        const map = new Map<string, ComponentVersionEntry[]>();
                                                        for (const v of versions()) {
                                                            const key = v.subjectVersion ?? v.sbomId;
                                                            if (!map.has(key)) { order.push(key); map.set(key, []); }
                                                            map.get(key)!.push(v);
                                                        }
                                                        return { order, map };
                                                    };

                                                    return (
                                                        <div class="table-wrapper">
                                                            <Show
                                                                when={hasArch()}
                                                                fallback={
                                                                    <table>
                                                                        <thead>
                                                                            <tr>
                                                                                <th>Artifact</th>
                                                                                <th>Version</th>
                                                                                <th>Digest</th>
                                                                                <th>Ingested</th>
                                                                            </tr>
                                                                        </thead>
                                                                        <tbody>
                                                                            <For each={versions()}>
                                                                                {(entry) => (
                                                                                    <tr>
                                                                                        <td>
                                                                                            <Show
                                                                                                when={entry.artifactId}
                                                                                                fallback={
                                                                                                    <A href={`/sboms/${entry.sbomId}`}>
                                                                                                        {formatDateTime(entry.sbomCreatedAt)}
                                                                                                    </A>
                                                                                                }
                                                                                            >
                                                                                                <A href={`/artifacts/${entry.artifactId}`}>
                                                                                                    {entry.artifactName ?? entry.artifactId!.slice(0, 8)}
                                                                                                </A>
                                                                                            </Show>
                                                                                        </td>
                                                                                        <td>
                                                                                            <Show
                                                                                                when={entry.subjectVersion}
                                                                                                fallback={<span class="text-muted">—</span>}
                                                                                            >
                                                                                                <span class="mono">{entry.subjectVersion}</span>
                                                                                            </Show>
                                                                                        </td>
                                                                                        <td>
                                                                                            <Show
                                                                                                when={entry.sbomDigest}
                                                                                                fallback={<span class="text-muted">—</span>}
                                                                                            >
                                                                                                <CopyDigest digest={entry.sbomDigest!} />
                                                                                            </Show>
                                                                                        </td>
                                                                                        <td
                                                                                            class="nowrap text-muted"
                                                                                            title={new Date(entry.sbomCreatedAt).toLocaleString()}
                                                                                        >
                                                                                            {relativeDate(entry.sbomCreatedAt)}
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
                                                                            <th>Artifact</th>
                                                                            <th>Version</th>
                                                                            <th>Architectures</th>
                                                                            <th>Ingested</th>
                                                                        </tr>
                                                                    </thead>
                                                                    <tbody>
                                                                        <For each={groups()!.order}>
                                                                            {(key) => {
                                                                                const entries = groups()!.map.get(key)!;
                                                                                const preferred = entries.find(e => e.architecture === "amd64") ?? entries[0];
                                                                                return (
                                                                                    <>
                                                                                        <tr style={{ "font-weight": "600" }}>
                                                                                            <td>
                                                                                                <Show
                                                                                                    when={preferred.artifactId}
                                                                                                    fallback={<span class="text-muted">—</span>}
                                                                                                >
                                                                                                    <A href={`/artifacts/${preferred.artifactId}`}>
                                                                                                        {preferred.artifactName ?? preferred.artifactId!.slice(0, 8)}
                                                                                                    </A>
                                                                                                </Show>
                                                                                            </td>
                                                                                            <td>
                                                                                                <A href={`/sboms/${preferred.sbomId}`} class="mono">
                                                                                                    {preferred.subjectVersion ?? key}
                                                                                                </A>
                                                                                            </td>
                                                                                            <td>
                                                                                                <For each={entries}>
                                                                                                    {(e) => (
                                                                                                        <span class="badge badge-primary" style={{ "margin-right": "4px" }}>
                                                                                                            {e.architecture}
                                                                                                        </span>
                                                                                                    )}
                                                                                                </For>
                                                                                            </td>
                                                                                            <td
                                                                                                class="nowrap text-muted"
                                                                                                title={new Date(preferred.sbomCreatedAt).toLocaleString()}
                                                                                            >
                                                                                                {relativeDate(preferred.sbomCreatedAt)}
                                                                                            </td>
                                                                                        </tr>
                                                                                        <For each={entries}>
                                                                                            {(e) => (
                                                                                                <tr style={{ background: "var(--color-bg-alt, #f8f9fa)" }}>
                                                                                                    <td style={{ "padding-left": "2rem" }} colspan={4}>
                                                                                                        <span class="badge badge-primary" style={{ "margin-right": "8px" }}>
                                                                                                            {e.architecture}
                                                                                                        </span>
                                                                                                        <A href={`/sboms/${e.sbomId}`} style={{ "margin-right": "12px" }}>
                                                                                                            SBOM
                                                                                                        </A>
                                                                                                        <Show when={e.artifactName}>
                                                                                                            <span class="text-muted text-sm">{e.artifactName}</span>
                                                                                                        </Show>
                                                                                                    </td>
                                                                                                </tr>
                                                                                            )}
                                                                                        </For>
                                                                                    </>
                                                                                );
                                                                            }}
                                                                        </For>
                                                                    </tbody>
                                                                </table>
                                                            </Show>
                                                        </div>
                                                    );
                                                })()}
                                            </Show>
                                        </Show>
                                    </Show>
                                </div>

                                <div class="card mb-md">
                                    <div class="card-header">
                                        <h3>Licenses</h3>
                                        <span class="badge">
                                            {licenses().length}
                                        </span>
                                    </div>
                                    <Show
                                        when={licenses().length > 0}
                                        fallback={
                                            <EmptyState
                                                title="No licenses"
                                                message="No license information is associated with this component."
                                            />
                                        }
                                    >
                                        <div class="table-wrapper">
                                            <table>
                                                <thead>
                                                    <tr>
                                                        <th>Name</th>
                                                        <th>SPDX ID</th>
                                                        <th>URL</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    <For each={licenses()}>
                                                        {(license) => (
                                                            <tr>
                                                                <td>
                                                                    <A
                                                                        href={`/licenses/${license.id}/components`}
                                                                    >
                                                                        {
                                                                            license.name
                                                                        }
                                                                    </A>
                                                                </td>
                                                                <td>
                                                                    <Show
                                                                        when={
                                                                            license.spdxId
                                                                        }
                                                                        fallback={
                                                                            <span class="text-muted">
                                                                                —
                                                                            </span>
                                                                        }
                                                                    >
                                                                        <span class="badge badge-primary">
                                                                            {
                                                                                license.spdxId
                                                                            }
                                                                        </span>
                                                                    </Show>
                                                                </td>
                                                                <td>
                                                                    <Show
                                                                        when={
                                                                            license.url
                                                                        }
                                                                        fallback={
                                                                            <span class="text-muted">
                                                                                —
                                                                            </span>
                                                                        }
                                                                    >
                                                                        <a
                                                                            href={
                                                                                license.url
                                                                            }
                                                                            target="_blank"
                                                                            rel="noopener noreferrer"
                                                                            class="text-sm"
                                                                        >
                                                                            {
                                                                                license.url
                                                                            }
                                                                        </a>
                                                                    </Show>
                                                                </td>
                                                            </tr>
                                                        )}
                                                    </For>
                                                </tbody>
                                            </table>
                                        </div>
                                    </Show>
                                </div>

                                <div class="card mb-md">
                                    <div class="card-header">
                                        <h3>Hashes</h3>
                                        <span class="badge">
                                            {hashes().length}
                                        </span>
                                    </div>
                                    <Show
                                        when={hashes().length > 0}
                                        fallback={
                                            <EmptyState
                                                title="No hashes"
                                                message="No hash values are recorded for this component."
                                            />
                                        }
                                    >
                                        <div class="table-wrapper">
                                            <table>
                                                <thead>
                                                    <tr>
                                                        <th>Algorithm</th>
                                                        <th>Value</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    <For each={hashes()}>
                                                        {(hash) => (
                                                            <tr>
                                                                <td>
                                                                    <span class="badge">
                                                                        {
                                                                            hash.algorithm
                                                                        }
                                                                    </span>
                                                                </td>
                                                                <td class="mono">
                                                                    {hash.value}
                                                                </td>
                                                            </tr>
                                                        )}
                                                    </For>
                                                </tbody>
                                            </table>
                                        </div>
                                    </Show>
                                </div>

                                <div class="card">
                                    <div class="card-header">
                                        <h3>External References</h3>
                                        <span class="badge">
                                            {externalRefs().length}
                                        </span>
                                    </div>
                                    <Show
                                        when={externalRefs().length > 0}
                                        fallback={
                                            <EmptyState
                                                title="No external references"
                                                message="No external references are recorded for this component."
                                            />
                                        }
                                    >
                                        <div class="table-wrapper">
                                            <table>
                                                <thead>
                                                    <tr>
                                                        <th>Type</th>
                                                        <th>URL</th>
                                                        <th>Comment</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    <For each={externalRefs()}>
                                                        {(ref) => (
                                                            <tr>
                                                                <td>
                                                                    <span class="badge">
                                                                        {
                                                                            ref.type
                                                                        }
                                                                    </span>
                                                                </td>
                                                                <td>
                                                                    <a
                                                                        href={
                                                                            ref.url
                                                                        }
                                                                        target="_blank"
                                                                        rel="noopener noreferrer"
                                                                        class="mono text-sm"
                                                                    >
                                                                        {
                                                                            ref.url
                                                                        }
                                                                    </a>
                                                                </td>
                                                                <td class="text-muted">
                                                                    {ref.comment ??
                                                                        "—"}
                                                                </td>
                                                            </tr>
                                                        )}
                                                    </For>
                                                </tbody>
                                            </table>
                                        </div>
                                    </Show>
                                </div>
                            </>
                        );
                    })()}
                </Show>
            </Show>
        </>
    );
}

function CopyDigest(props: { digest: string }) {
    const [copied, setCopied] = createSignal(false);

    const copy = async () => {
        try {
            await navigator.clipboard.writeText(props.digest);
        } catch {
            const ta = document.createElement("textarea");
            ta.value = props.digest;
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
            title={`Click to copy: ${props.digest}`}
            onClick={copy}
        >
            {copied() ? "Copied!" : shortDigest(props.digest)}
        </button>
    );
}
