import { createMemo, Show } from "solid-js";
import { A, useSearchParams } from "@solidjs/router";
import { useArtifactsInfinite } from "~/api/queries";
import DataTable from "~/components/DataTable";
import type { Column, SortDir } from "~/components/DataTable";
import { VulnCountBadges } from "~/components/VulnBadge";
import { artifactDisplayName, plural } from "~/utils/format";
import { SigningBadge, TypeBadge } from "~/components/cells";
import { DEFAULT_PAGE_SIZE, type ArtifactSummary } from "~/api/client";
import { PageHeader, Toolbar } from "~/components/ui";
import type { ToolbarField } from "~/components/ui";

const ARTIFACT_TYPES = [
    "application",
    "container",
    "cryptographic-asset",
    "data",
    "device",
    "device-driver",
    "file",
    "firmware",
    "framework",
    "library",
    "machine-learning-model",
    "operating-system",
    "platform",
];

const FILTERS: ToolbarField[] = [
    { kind: "text", key: "name", placeholder: "Filter by name…", label: "Filter by name" },
    {
        kind: "select",
        key: "type",
        options: ARTIFACT_TYPES,
        allLabel: "All types",
        label: "Artifact type",
    },
    { kind: "checkbox", key: "all", label: "Show all" },
];

/** How a group of artifacts got its heading, which decides how it renders. */
type GroupKind = "path" | "group" | "type";

interface ArtifactGroup {
    key: string;
    kind: GroupKind;
    items: ArtifactSummary[];
}

// Grouping used to parse *every* artifact name as an OCI repository path. That
// is only meaningful for containers: a library named "mylib" became a group of
// one called "mylib", and a binary with no slash in its name got a heading that
// just repeated the row beneath it. Now that ADR-040 admits non-container
// artifacts, the heading follows the identity the type actually has —
// registry path for containers, purl group where there is one, type otherwise.
function groupOf(a: ArtifactSummary): { key: string; kind: GroupKind } {
    if (a.type === "container") {
        const parts = a.name.split("/");
        return {
            key: parts.length >= 2 ? `${parts[0]}/${parts[1]}` : parts[0],
            kind: "path",
        };
    }
    if (a.group !== undefined && a.group !== "") {
        return { key: a.group, kind: "group" };
    }
    return { key: a.type, kind: "type" };
}

// The grouping key travels through DataTable as a single string, so kind rides
// along in a prefix rather than in a parallel lookup. `key` may itself contain
// a colon (a purl group can), so only the first one separates.
const groupKey = (a: ArtifactSummary): string => {
    const { key, kind } = groupOf(a);
    return `${kind}:${key}`;
};

const columns: Column<ArtifactSummary>[] = [
    {
        header: "Artifact",
        render: (a) => <A href={`/artifacts/${a.id}`}>{artifactDisplayName(a)}</A>,
    },
    {
        header: "Type",
        render: (a) => <TypeBadge type={a.type} />,
    },
    {
        header: "Signing",
        render: (a) => <SigningBadge status={a.signingStatus} />,
    },
    {
        header: "Vulnerabilities",
        sortKey: "severity",
        sortType: "numeric",
        render: (a) => (
            // `vulns` is absent when the artifact's newest SBOM has no rollup
            // row, which means "no findings" or "never scanned" without
            // distinguishing them. Rendering that as a zero — or as
            // VulnCountBadges' own em dash, which reads the same — would claim
            // a clean bill of health nobody issued (ADR-044).
            <Show
                when={a.vulns}
                fallback={
                    <span class="text-muted" title="No findings recorded for this artifact — it may never have been scanned">
                        not scanned
                    </span>
                }
            >
                {(v) => (
                    <VulnCountBadges
                        criticalCount={v().critical}
                        highCount={v().high}
                        mediumCount={v().medium}
                        lowCount={v().low}
                        unknownCount={v().unknown}
                    />
                )}
            </Show>
        ),
    },
    {
        header: "SBOMs",
        render: (a) => plural(a.sbomCount, "SBOM"),
    },
];

export default function Artifacts() {
    // Every filter now lives in the URL, not just the type. Home's breakdown
    // chips already linked into `?type=`; name and "show all" were local
    // signals, so the one view a reader would actually want to send someone —
    // "these artifacts, filtered this way" — was the one that could not be
    // linked to or survive a reload.
    const [searchParams, setSearchParams] = useSearchParams();
    const param = (key: string): string => {
        const v = searchParams[key];
        return (Array.isArray(v) ? v[0] : v) ?? "";
    };

    // The sort lives in the URL for the same reason the filters do: "the worst
    // artifacts we have, worst first" is precisely the view someone wants to
    // send to someone else.
    const sortBy = () => (param("sort") === "severity" ? "severity" : undefined);
    const sortDir = (): SortDir => (param("dir") === "asc" ? "asc" : "desc");

    const query = useArtifactsInfinite(() => ({
        name: param("name"),
        type: param("type"),
        limit: DEFAULT_PAGE_SIZE,
        // "Show all" lifts a constraint rather than adding one: unchecked, the
        // list is limited to artifacts whose SBOMs are substantial enough to
        // say anything about.
        sufficient: param("all") !== "1",
        // Sorting is server-side: the list is paged, so a client-side sort
        // would only reorder the rows fetched so far.
        sort: sortBy(),
        dir: sortBy() === undefined ? undefined : sortDir(),
    }));

    const rawArtifacts = () => query.data?.pages.flatMap((p) => p.data ?? []) ?? [];

    // Grouping is dropped under the severity sort. The two are incompatible by
    // construction: DataTable only labels runs of equal keys, so grouping means
    // re-collecting rows by name, which would undo the ordering the server just
    // applied. A flat worst-first list is what the sort was asked for anyway.
    const artifacts = () => (sortBy() === undefined ? grouped().flatMap((g) => g.items) : rawArtifacts());

    // Still grouped here rather than in DataTable: the table only labels runs of
    // equal keys, it does not reorder, so the rows have to arrive grouped.
    const grouped = createMemo((): ArtifactGroup[] => {
        const map = new Map<string, ArtifactGroup>();
        for (const a of rawArtifacts()) {
            const { key, kind } = groupOf(a);
            // Key on kind too: a purl group could legitimately be called
            // "library" and must not silently merge into the type bucket.
            const mapKey = `${kind}:${key}`;
            const bucket = map.get(mapKey);
            if (bucket) {
                bucket.items.push(a);
            } else {
                map.set(mapKey, { key, kind, items: [a] });
            }
        }
        return [...map.values()];
    });

    // A single heading spanning the whole table is noise — it repeats what the
    // filters already say. Headings earn their row only once there is more than
    // one thing to tell apart.
    const showGroupHeadings = () => sortBy() === undefined && grouped().length > 1;

    // Changing the sort re-orders the whole result set server-side, so every
    // page already loaded is stale — dropping the cursor restarts from page one.
    const sortArtifacts = (key: string, dir: SortDir) => {
        setSearchParams({
            sort: key === "severity" ? "severity" : undefined,
            dir: key === "severity" ? dir : undefined,
        });
    };

    return (
        <>
            <PageHeader
                title="Artifacts"
                subtitle="Software artifacts (container images, libraries, applications) tracked by OCIDex"
            />

            <Toolbar class="mb-4" fields={FILTERS} />

            <DataTable
                columns={columns}
                rows={query.data === undefined ? undefined : artifacts()}
                sortBy={sortBy()}
                sortDir={sortDir()}
                onSort={sortArtifacts}
                loading={query.isFetching}
                isError={query.isError}
                error={query.error}
                emptyTitle="No artifacts found"
                emptyMessage="Ingest an SBOM to get started."
                groupBy={
                    showGroupHeadings()
                        ? {
                              key: groupKey,
                              header: (key, count) => {
                                  const sep = key.indexOf(":");
                                  const kind = key.slice(0, sep);
                                  const label = key.slice(sep + 1);
                                  return (
                                      <>
                                          {kind === "type" ? <TypeBadge type={label} /> : label}{" "}
                                          <span class="group-header-count">{count}</span>
                                      </>
                                  );
                              },
                          }
                        : undefined
                }
                loadMore={{
                    hasMore: query.hasNextPage,
                    loading: query.isFetchingNextPage,
                    onClick: () => void query.fetchNextPage(),
                }}
            />
        </>
    );
}
