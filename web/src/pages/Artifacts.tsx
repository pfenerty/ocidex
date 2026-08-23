import { createMemo, createSignal, For } from "solid-js";
import { A, useSearchParams } from "@solidjs/router";
import { useArtifactsInfinite } from "~/api/queries";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { artifactDisplayName, plural } from "~/utils/format";
import { SigningBadge, TypeBadge } from "~/components/cells";
import { DEFAULT_PAGE_SIZE, type ArtifactSummary } from "~/api/client";
import { PageHeader } from "~/components/ui";

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
        header: "SBOMs",
        render: (a) => plural(a.sbomCount, "SBOM"),
    },
];

export default function Artifacts() {
    const [nameFilter, setNameFilter] = createSignal("");
    const [showAll, setShowAll] = createSignal(false);

    // The type filter lives in the URL so Home's breakdown chips can link
    // straight into a filtered list, and so a filtered view survives a reload.
    // Name and "show all" stay local — nothing links to them.
    const [searchParams, setSearchParams] = useSearchParams();
    const typeFilter = () => {
        const t = searchParams.type;
        return (Array.isArray(t) ? t[0] : t) ?? "";
    };

    let nameDebounce: ReturnType<typeof setTimeout>;
    const handleNameInput = (val: string) => {
        clearTimeout(nameDebounce);
        nameDebounce = setTimeout(() => setNameFilter(val), 300);
    };

    const query = useArtifactsInfinite(() => ({
        name: nameFilter(),
        type: typeFilter(),
        limit: DEFAULT_PAGE_SIZE,
        sufficient: showAll() ? false : true,
    }));

    const rawArtifacts = () => query.data?.pages.flatMap((p) => p.data ?? []) ?? [];
    const artifacts = () => grouped().flatMap((g) => g.items);

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
    const showGroupHeadings = () => grouped().length > 1;

    return (
        <>
            <PageHeader
                title="Artifacts"
                subtitle="Software artifacts (container images, libraries, applications) tracked by OCIDex"
            />

            <div class="search-bar mb-4">
                <input
                    type="text"
                    placeholder="Filter by name…"
                    onInput={(e) => handleNameInput(e.currentTarget.value)}
                />
                <select
                    value={typeFilter()}
                    onChange={(e) =>
                        setSearchParams({
                            type: e.currentTarget.value === "" ? undefined : e.currentTarget.value,
                        })
                    }
                >
                    <option value="">All types</option>
                    <For each={ARTIFACT_TYPES}>
                        {(t) => <option value={t}>{t}</option>}
                    </For>
                </select>
                <label style={{ display: "flex", "align-items": "center", gap: "0.5rem", cursor: "pointer", "white-space": "nowrap" }}>
                    <input
                        type="checkbox"
                        checked={showAll()}
                        onChange={(e) => setShowAll(e.currentTarget.checked)}
                    />
                    Show all
                </label>
            </div>

            <DataTable
                columns={columns}
                rows={query.data === undefined ? undefined : artifacts()}
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
