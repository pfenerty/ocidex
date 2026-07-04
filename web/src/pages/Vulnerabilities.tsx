import { createSignal, Show, For } from "solid-js";
import { A } from "@solidjs/router";
import { useTopVulnerabilities } from "~/api/queries";
import { Loading, ErrorBox, EmptyState } from "~/components/Feedback";
import Pagination from "~/components/Pagination";
import { StatusPill } from "~/components/ui/Badge";
import { severityVariant } from "~/components/VulnBadge";

const SEVERITY_TABS = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
const limit = 50;

export default function Vulnerabilities() {
    const [offset, setOffset] = createSignal(0);
    const [severityFilter, setSeverityFilter] = createSignal("");

    const query = useTopVulnerabilities(() => ({
        limit,
        offset: offset(),
        severity: severityFilter(),
    }));

    const handleTabChange = (tab: string) => {
        setSeverityFilter(tab === "All" ? "" : tab);
        setOffset(0);
    };

    const formatDate = (iso: string | undefined) =>
        iso ? new Date(iso).toLocaleDateString() : "—";

    return (
        <>
            <div class="page-header">
                <div class="page-header-row">
                    <div>
                        <h2>Vulnerabilities</h2>
                        <p>
                            Most-found CVEs across all tracked artifacts
                            <Show when={query.data}>
                                {(d) => (
                                    <span class="text-muted">
                                        {" "}
                                        &mdash;{" "}
                                        {d().pagination.total.toLocaleString()}{" "}
                                        total
                                    </span>
                                )}
                            </Show>
                        </p>
                    </div>
                </div>

                <div class="tab-bar">
                    <For each={SEVERITY_TABS}>
                        {(tab) => (
                            <button
                                class={`tab-btn${(tab === "All" ? "" : tab) === severityFilter() ? " tab-active" : ""}`}
                                onClick={() => handleTabChange(tab)}
                            >
                                {tab}
                            </button>
                        )}
                    </For>
                </div>
            </div>

            <Show when={!query.isLoading} fallback={<Loading />}>
                <Show
                    when={!query.isError}
                    fallback={<ErrorBox error={query.error} />}
                >
                    <Show
                        when={query.data && (query.data.data?.length ?? 0) > 0}
                        fallback={
                            <EmptyState title="No vulnerabilities found." />
                        }
                    >
                        {(_) => {
                            const d = () => query.data!;
                            return (
                                <div class="card">
                                    <div class="table-wrapper">
                                        <table>
                                            <thead>
                                                <tr>
                                                    <th>CVE ID</th>
                                                    <th>Severity</th>
                                                    <th class="text-right">
                                                        CVSS
                                                    </th>
                                                    <th>Summary</th>
                                                    <th class="text-right">
                                                        Affected SBOMs
                                                    </th>
                                                    <th class="text-right">
                                                        Affected Packages
                                                    </th>
                                                    <th>Published</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <For
                                                    each={
                                                        d().data?.filter(
                                                            Boolean,
                                                        ) ?? []
                                                    }
                                                >
                                                    {(row) => (
                                                        <tr>
                                                            <td>
                                                                <A
                                                                    href={`/vulnerabilities/${row.id}`}
                                                                >
                                                                    <code>
                                                                        {
                                                                            row.id
                                                                        }
                                                                    </code>
                                                                </A>
                                                            </td>
                                                            <td>
                                                                <StatusPill
                                                                    variant={severityVariant(
                                                                        row.severity,
                                                                    )}
                                                                >
                                                                    {
                                                                        row.severity
                                                                    }
                                                                </StatusPill>
                                                            </td>
                                                            <td class="text-right">
                                                                {row.cvssScore !==
                                                                undefined
                                                                    ? row.cvssScore.toFixed(
                                                                          1,
                                                                      )
                                                                    : "—"}
                                                            </td>
                                                            <td class="text-muted">
                                                                {row.summary ??
                                                                    "—"}
                                                            </td>
                                                            <td class="text-right">
                                                                {row.affectedSbomCount.toLocaleString()}
                                                            </td>
                                                            <td class="text-right">
                                                                {row.affectedPurlCount.toLocaleString()}
                                                            </td>
                                                            <td class="text-muted">
                                                                {formatDate(
                                                                    row.publishedAt,
                                                                )}
                                                            </td>
                                                        </tr>
                                                    )}
                                                </For>
                                            </tbody>
                                        </table>
                                    </div>
                                    <Pagination
                                        pagination={d().pagination}
                                        onPageChange={setOffset}
                                    />
                                </div>
                            );
                        }}
                    </Show>
                </Show>
            </Show>
        </>
    );
}
