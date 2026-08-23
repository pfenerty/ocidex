import { createQuery } from "@tanstack/solid-query";
import type { Accessor } from "solid-js";
import { client, unwrap } from "~/api/client";

/** The shortest term worth a round trip. One character matches most of the corpus. */
export const MIN_SEARCH_TERM = 2;

/** How many rows each of the four searches may contribute. */
const PER_GROUP_LIMIT = 5;

/** One row in the palette, whatever it was found in. */
export interface SearchHit {
    /** Stable within its group; used as the list key. */
    key: string;
    label: string;
    /** Second line: the qualifier that tells two same-named hits apart. */
    sub?: string;
    /** Where Enter goes. */
    path: string;
}

/**
 * The four searches behind the command palette.
 *
 * Written here rather than reusing the list pages' hooks for one reason: those
 * fetch unconditionally, and the palette must be able to open — which it does on
 * every Cmd-K, whether or not anyone types — without firing four requests at a
 * catalog nobody has asked about yet. `enabled` is the whole difference, plus a
 * `select` that flattens four unrelated row shapes into one `SearchHit`.
 *
 * **Staleness is TanStack's problem, not ours.** Each debounced term is its own
 * query key, so a slow response for "open" cannot overwrite the rendered results
 * for "openssl" — it resolves into its own cache entry, which nothing is reading
 * any more. That is the in-flight cancellation the story asks for; a hand-rolled
 * request counter would only re-implement it worse.
 *
 * `retry: false` matters for a signed-out visitor: a 401 here is an answer, not
 * a failure to retry, and since ocidex-ag4q.1 it no longer navigates anywhere.
 * The caller renders an errored group as absent.
 */
function searchQuery<R>(
    name: string,
    term: Accessor<string>,
    fetcher: (q: string) => Promise<R>,
    toHits: (resp: R) => SearchHit[],
) {
    return createQuery(() => {
        const q = term();
        return {
            queryKey: ["palette-search", name, q] as const,
            queryFn: () => fetcher(q),
            enabled: q.length >= MIN_SEARCH_TERM,
            retry: false,
            // Hold the previous term's rows while the next ones land, so the
            // list narrows instead of blinking empty between keystrokes.
            keepPreviousData: true,
            staleTime: 30_000,
            select: toHits,
        };
    });
}

export function useArtifactSearch(term: Accessor<string>) {
    return searchQuery(
        "artifacts",
        term,
        (q) =>
            unwrap(
                client.GET("/api/v1/artifacts", {
                    params: { query: { name: q, limit: PER_GROUP_LIMIT } },
                }),
            ),
        (resp) =>
            (resp.data ?? []).map((a) => ({
                key: a.id,
                label: a.group !== undefined && a.group !== "" ? `${a.group}/${a.name}` : a.name,
                sub: a.type,
                path: `/artifacts/${a.id}`,
            })),
    );
}

export function useComponentSearch(term: Accessor<string>) {
    return searchQuery(
        "components",
        term,
        (q) =>
            unwrap(
                client.GET("/api/v1/components/distinct", {
                    // Sorted by version count, not by name. The corpus holds a
                    // *file* component per path, so an alphabetical top five for
                    // "openssl" is /etc/pki/.../README and friends and the
                    // openssl package never appears. Files have no versions, so
                    // ranking by version count floats real packages to the top.
                    params: {
                        query: {
                            name: q,
                            limit: PER_GROUP_LIMIT,
                            sort: "version_count",
                            sort_dir: "desc",
                        },
                    },
                }),
            ),
        (resp) =>
            (resp.data ?? []).map((c) => {
                // Components are deduplicated by name+group and have no id of
                // their own, so the destination is the overview keyed the same
                // way — exactly what the Components table links to.
                const params = new URLSearchParams({ name: c.name });
                if (c.group !== undefined && c.group !== "") params.set("group", c.group);
                return {
                    key: `${c.group ?? ""}/${c.name}`,
                    label: c.group !== undefined && c.group !== "" ? `${c.group}/${c.name}` : c.name,
                    sub: `${c.versionCount} version${c.versionCount === 1 ? "" : "s"}`,
                    path: `/components/overview?${params.toString()}`,
                };
            }),
    );
}

export function useVulnerabilitySearch(term: Accessor<string>) {
    return searchQuery(
        "vulns",
        term,
        (q) =>
            unwrap(
                client.GET("/api/v1/vulns", {
                    params: { query: { q, limit: PER_GROUP_LIMIT } },
                }),
            ),
        (resp) =>
            (resp.data ?? []).map((v) => {
                // `canonicalId` is a non-nullable string in the generated type,
                // but it is empty for a vulnerability with no canonical alias —
                // `||`, not `??`, which is also what VulnId does.
                const id = v.canonicalId || v.id;
                return {
                    key: v.id,
                    label: id,
                    sub: v.severity,
                    path: `/vulnerabilities/${encodeURIComponent(id)}`,
                };
            }),
    );
}

export function useLicenseSearch(term: Accessor<string>) {
    return searchQuery(
        "licenses",
        term,
        (q) =>
            unwrap(
                client.GET("/api/v1/licenses", {
                    params: { query: { name: q, limit: PER_GROUP_LIMIT } },
                }),
            ),
        (resp) =>
            (resp.data ?? []).map((l) => ({
                key: l.id,
                label: l.name,
                sub: l.spdxId,
                path: `/licenses/${l.id}/components`,
            })),
    );
}
