import "~/components/DetailSection.css";
import { Show, createSignal } from "solid-js";
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
import { Card, CardHeader, TabBar } from "~/components/ui";
import type { TabDef } from "~/components/ui";

type ComponentVulnEntry = components["schemas"]["ComponentVulnEntry"];

const vulnColumns: Column<ComponentVulnEntry>[] = [
    {
        header: "Vulnerability",
        render: (v) => (
            <>
                <VulnId canonicalId={v.canonicalId} nativeId={v.id} />
                <Show when={v.matchedViaSource}>
                    <span class="ml-2">
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

type ExternalRefEntry = components["schemas"]["ExternalRefEntry"];

const externalRefColumns: Column<ExternalRefEntry>[] = [
    {
        header: "Type",
        render: (ref) => <span class="badge">{ref.type}</span>,
    },
    {
        header: "URL",
        render: (ref) => (
            <a href={ref.url} target="_blank" rel="noopener noreferrer" class="font-mono text-sm">
                {ref.url}
            </a>
        ),
    },
    {
        header: "Comment",
        render: (ref) => <span class="text-muted">{ref.comment ?? "—"}</span>,
    },
];

/** The sections of a component's metadata, one per tab. */
export type ComponentTab = "details" | "vulns" | "licenses";

/**
 * Renders the full metadata for a single component instance: the identity
 * detail-grid, description, and the vulnerabilities / licenses / hashes /
 * external-references tables. Shared by ComponentOverview (drill-down view)
 * and the ComponentDetail page (/components/:id).
 *
 * The four tables used to be stacked, so the two a reader actually arrives with
 * a question about — vulnerabilities and licences — sat below a detail grid and
 * a description of unbounded length, with hashes they never asked for wedged
 * between them. They are tabs now; hashes and external references fold into
 * Details rather than earning a tab of their own (ocidex-ag4q.35).
 *
 * `tab`/`onTabChange` are optional: supplied, the caller drives the selection
 * (so a summary tile can open a tab); omitted, the component keeps its own.
 *
 * Callers pass their already-created queries so no double-fetching occurs.
 * `showVulns` gates the vulnerabilities tab (typically on whether the
 * component has a purl, since vuln matching is purl-based).
 */
export default function ComponentMetadata(props: {
    detailQuery: ReturnType<typeof useComponent>;
    vulnsQuery: ReturnType<typeof useComponentVulns>;
    showVulns: boolean;
    tab?: ComponentTab;
    onTabChange?: (tab: ComponentTab) => void;
}) {
    const [ownTab, setOwnTab] = createSignal<ComponentTab>("details");
    const tab = (): ComponentTab => props.tab ?? ownTab();
    const selectTab = (t: ComponentTab): void => {
        setOwnTab(t);
        props.onTabChange?.(t);
    };

    const licenseCount = (): number => (props.detailQuery.data?.licenses ?? []).length;
    const vulnCount = (): number => props.vulnsQuery.data?.data.length ?? 0;

    const tabs = (): TabDef<ComponentTab>[] => {
        const t: TabDef<ComponentTab>[] = [{ id: "details", label: "Details" }];
        // Counts ride in the label so a reader can tell an empty tab from a
        // full one without opening it — which is what a tab strip owes them in
        // exchange for hiding the content.
        if (props.showVulns) {
            t.push({ id: "vulns", label: `Vulnerabilities (${vulnCount()})` });
        }
        t.push({ id: "licenses", label: `Licenses (${licenseCount()})` });
        return t;
    };

    // A vulnerabilities tab that stops existing (a component whose purl is
    // still loading) must not leave the reader on a blank panel.
    const activeTab = (): ComponentTab =>
        tab() === "vulns" && !props.showVulns ? "details" : tab();

    return (
        <>
            <TabBar tabs={tabs()} active={activeTab()} onSelect={selectTab} class="mb-4" />

            {/* ── Details ── */}
            <Show when={activeTab() === "details" ? props.detailQuery.data : undefined} keyed>
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
                                            <span class="ml-2">
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
                                            <span class="ml-2">
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
                            <Card class="mb-4">
                                <CardHeader title="Description" />
                                <p class="text-sm">{detail.description}</p>
                            </Card>
                        </Show>
                    </>
                )}
            </Show>

            {/* ── Vulnerabilities ── */}
            <Show when={activeTab() === "vulns" && props.showVulns}>
                <div class="mb-4">
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

            {/* ── Licenses ── */}
            <Show when={activeTab() === "licenses"}>
                <div class="mb-4">
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
            </Show>

            {/* Hashes and external references are Details' own content: nobody
                arrives asking for them, but they belong beside the identity
                fields rather than behind a tab of their own. */}
            <Show when={activeTab() === "details"}>
                <div class="mb-4">
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
            </Show>

            {/* External References */}
            <Show
                when={
                    activeTab() === "details" &&
                    (props.detailQuery.data?.externalReferences ?? []).length > 0
                }
            >
                <DataTable
                    class="mb-4"
                    caption={
                        <CardHeader
                            title="External References"
                            count={(props.detailQuery.data?.externalReferences ?? []).length}
                        />
                    }
                    columns={externalRefColumns}
                    rows={props.detailQuery.data?.externalReferences ?? []}
                    loading={false}
                    isError={false}
                    emptyTitle="No external references"
                />
            </Show>
        </>
    );
}
