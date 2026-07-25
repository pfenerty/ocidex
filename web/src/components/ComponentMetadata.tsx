import "~/components/DetailSection.css";
import { Show, For } from "solid-js";
import { A } from "@solidjs/router";
import type { useComponent, useComponentVulns } from "~/api/queries";
import type { LicenseSummary, HashEntry } from "~/api/client";
import type { components } from "~/types/openapi";
import PurlLink from "~/components/PurlLink";
import { StatusPill } from "~/components/ui/Badge";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { SeverityPill, VulnId, SpdxBadgeCell } from "~/components/cells";
import { hasText } from "~/utils/format";

type ComponentVulnEntry = components["schemas"]["ComponentVulnEntry"];

const vulnColumns: Column<ComponentVulnEntry>[] = [
    {
        header: "Vulnerability",
        render: (v) => (
            <>
                <VulnId canonicalId={v.canonicalId} nativeId={v.id} />
                <Show when={v.matchedViaSource}>
                    <span style={{ "margin-left": "8px" }}>
                        <StatusPill
                            variant="default"
                            title="Matched via the component's source package, not its own purl"
                        >
                            via source
                        </StatusPill>
                    </span>
                </Show>
            </>
        ),
    },
    {
        header: "Severity",
        render: (v) => <SeverityPill severity={v.severity}>{v.severity}</SeverityPill>,
    },
    {
        header: "CVSS",
        render: (v) => v.cvssScore?.toFixed(1) ?? "—",
    },
    {
        header: "Summary",
        render: (v) => <span class="text-muted">{v.summary ?? "—"}</span>,
    },
    {
        header: "Fixed In",
        render: (v) => <span class="font-mono text-sm">{v.fixedVersion ?? "—"}</span>,
    },
];

const licenseColumns: Column<LicenseSummary>[] = [
    {
        header: "Name",
        render: (license) => (
            <A href={`/licenses/${license.id}/components`}>{license.name}</A>
        ),
    },
    {
        header: "SPDX ID",
        render: (license) => <SpdxBadgeCell spdxId={license.spdxId} />,
    },
    {
        header: "URL",
        render: (license) => (
            <Show when={license.url} fallback={<span class="text-muted">—</span>}>
                {(url) => (
                    <a href={url()} target="_blank" rel="noopener noreferrer" class="text-sm">
                        {url()}
                    </a>
                )}
            </Show>
        ),
    },
];

const hashColumns: Column<HashEntry>[] = [
    {
        header: "Algorithm",
        render: (hash) => <span class="badge">{hash.algorithm}</span>,
    },
    {
        header: "Value",
        render: (hash) => <span class="font-mono text-sm">{hash.value}</span>,
    },
];

/**
 * Renders the full metadata for a single component instance: the identity
 * detail-grid, description, and the vulnerabilities / licenses / hashes /
 * external-references tables. Shared by ComponentOverview (drill-down view)
 * and the ComponentDetail page (/components/:id).
 *
 * Callers pass their already-created queries so no double-fetching occurs.
 * `showVulns` gates the vulnerabilities table (typically on whether the
 * component has a purl, since vuln matching is purl-based).
 */
export default function ComponentMetadata(props: {
    detailQuery: ReturnType<typeof useComponent>;
    vulnsQuery: ReturnType<typeof useComponentVulns>;
    showVulns: boolean;
}) {
    return (
        <>
            {/* Component metadata */}
            <Show when={props.detailQuery.data} keyed>
                {(detail) => (
                    <>
                        <div class="detail-grid">
                            <div class="detail-field">
                                <span class="detail-label">Type</span>
                                <span class="detail-value">{detail.type}</span>
                            </div>
                            <Show when={hasText(detail.group)}>
                                <div class="detail-field">
                                    <span class="detail-label">Group</span>
                                    <span class="detail-value">{detail.group}</span>
                                </div>
                            </Show>
                            <Show when={hasText(detail.purl)}>
                                <div class="detail-field">
                                    <span class="detail-label">PURL</span>
                                    <span class="detail-value">
                                        <PurlLink purl={detail.purl ?? ""} showBadge />
                                    </span>
                                </div>
                            </Show>
                            <Show when={hasText(detail.cpe)}>
                                <div class="detail-field">
                                    <span class="detail-label">CPE</span>
                                    <span class="detail-value font-mono text-sm">{detail.cpe}</span>
                                </div>
                            </Show>
                            <Show when={hasText(detail.scope)}>
                                <div class="detail-field">
                                    <span class="detail-label">Scope</span>
                                    <span class="detail-value">{detail.scope}</span>
                                </div>
                            </Show>
                            <Show when={hasText(detail.publisher)}>
                                <div class="detail-field">
                                    <span class="detail-label">Publisher</span>
                                    <span class="detail-value">{detail.publisher}</span>
                                </div>
                            </Show>
                            <Show when={hasText(detail.copyright)}>
                                <div class="detail-field">
                                    <span class="detail-label">Copyright</span>
                                    <span class="detail-value">{detail.copyright}</span>
                                </div>
                            </Show>
                            <Show when={hasText(detail.foundBy)}>
                                <div class="detail-field">
                                    <span class="detail-label">Detected by</span>
                                    <span class="detail-value">
                                        {detail.foundBy}
                                        <Show when={hasText(detail.confidence)}>
                                            <span style={{ "margin-left": "8px" }}>
                                                <StatusPill variant="warning">
                                                    {detail.confidence} confidence
                                                </StatusPill>
                                            </span>
                                        </Show>
                                    </span>
                                </div>
                            </Show>
                            <Show when={hasText(detail.sourcePackage)}>
                                <div class="detail-field">
                                    <span class="detail-label">Source package</span>
                                    <span class="detail-value">{detail.sourcePackage}</span>
                                </div>
                            </Show>
                            <Show when={detail.layer !== undefined}>
                                <div class="detail-field">
                                    <span class="detail-label">Layer</span>
                                    <span class="detail-value">
                                        {detail.layer}
                                        <Show when={detail.fromBaseImage}>
                                            <span style={{ "margin-left": "8px" }}>
                                                <StatusPill
                                                    variant="primary"
                                                    title="Introduced by the image's base layer"
                                                >
                                                    base image
                                                </StatusPill>
                                            </span>
                                        </Show>
                                    </span>
                                </div>
                            </Show>
                        </div>

                        <Show when={hasText(detail.description)}>
                            <div class="card mb-4">
                                <div class="card-header">
                                    <h3>Description</h3>
                                </div>
                                <p class="text-sm">{detail.description}</p>
                            </div>
                        </Show>
                    </>
                )}
            </Show>

            {/* Vulnerabilities */}
            <Show when={props.showVulns}>
                <div class="mb-4">
                    <h3>
                        Vulnerabilities{" "}
                        <Show when={props.vulnsQuery.data} keyed>
                            {(d) => (
                                <span class="badge">{d.data.length}</span>
                            )}
                        </Show>
                    </h3>
                    <DataTable
                        columns={vulnColumns}
                        rows={props.vulnsQuery.data?.data}
                        loading={props.vulnsQuery.isFetching}
                        isError={props.vulnsQuery.isError}
                        error={props.vulnsQuery.error}
                        emptyTitle="No known vulnerabilities"
                        emptyMessage="No vulnerabilities are currently recorded for this package."
                    />
                </div>
            </Show>

            {/* Licenses */}
            <div class="mb-4">
                <h3>
                    Licenses{" "}
                    <Show when={props.detailQuery.data} keyed>
                        {(d) => (
                            <span class="badge">{(d.licenses ?? []).length}</span>
                        )}
                    </Show>
                </h3>
                <DataTable
                    columns={licenseColumns}
                    rows={props.detailQuery.data?.licenses ?? undefined}
                    loading={props.detailQuery.isFetching}
                    isError={props.detailQuery.isError}
                    error={props.detailQuery.error}
                    emptyTitle="No licenses"
                    emptyMessage="No license information found for this component."
                />
            </div>

            {/* Hashes */}
            <div class="mb-4">
                <h3>
                    Hashes{" "}
                    <Show when={props.detailQuery.data} keyed>
                        {(d) => (
                            <span class="badge">{(d.hashes ?? []).length}</span>
                        )}
                    </Show>
                </h3>
                <DataTable
                    columns={hashColumns}
                    rows={props.detailQuery.data?.hashes ?? undefined}
                    loading={props.detailQuery.isFetching}
                    isError={props.detailQuery.isError}
                    error={props.detailQuery.error}
                    emptyTitle="No hashes"
                    emptyMessage="No hash information found for this component."
                />
            </div>

            {/* External References */}
            <Show when={(props.detailQuery.data?.externalReferences ?? []).length > 0}>
                <div class="card mb-4">
                    <div class="card-header">
                        <h3>External References</h3>
                        <span class="badge">{(props.detailQuery.data?.externalReferences ?? []).length}</span>
                    </div>
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
                                <For each={props.detailQuery.data?.externalReferences ?? []}>
                                    {(ref) => (
                                        <tr>
                                            <td>
                                                <span class="badge">{ref.type}</span>
                                            </td>
                                            <td>
                                                <a
                                                    href={ref.url}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    class="font-mono text-sm"
                                                >
                                                    {ref.url}
                                                </a>
                                            </td>
                                            <td class="text-muted">{ref.comment ?? "—"}</td>
                                        </tr>
                                    )}
                                </For>
                            </tbody>
                        </table>
                    </div>
                </div>
            </Show>
        </>
    );
}
