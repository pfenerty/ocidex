import "./AccountIdCard.css";
import { For, Show, type JSX } from "solid-js";
import { useAuth } from "~/context/auth";
import { useListAPIKeys, useListSources, useMyClusters, useMyNamespaces, useWatches } from "~/api/queries";
import { plural } from "~/utils/format";

/** One badge: earned from the account's real state, or an outline until it is. */
export interface Badge {
    id: string;
    label: string;
    /** What earns it, for the tooltip. */
    how: string;
    shape: "square" | "diamond";
    earned: boolean;
}

/**
 * The badges an account can earn, each from state the existing queries
 * already return. A badge with no data behind it is left out rather than shown
 * unearnable: a watched artifact going shiny would need vulnerability state per
 * watch, which the watches query does not carry.
 */
export function accountBadges(state: {
    namespaceIds: readonly string[];
    sources: readonly { kind: string; namespaceId: string }[];
    clusters: readonly { lastSeenAt?: string }[];
    apiKeyCount: number;
}): Badge[] {
    const mine = new Set(state.namespaceIds);
    return [
        {
            id: "registry",
            label: "First registry",
            how: "Connect an OCI registry to one of your namespaces",
            shape: "square",
            earned: state.sources.some((s) => s.kind === "oci_registry" && mine.has(s.namespaceId)),
        },
        {
            id: "cluster",
            label: "Cluster reporting",
            how: "Have a cluster agent report in",
            shape: "diamond",
            earned: state.clusters.some((c) => c.lastSeenAt !== undefined && c.lastSeenAt !== ""),
        },
        {
            id: "api-key",
            label: "First API key",
            how: "Create an API key",
            shape: "square",
            earned: state.apiKeyCount > 0,
        },
    ];
}

/**
 * The Account tab's ID card: who this is, how much of the catalog is theirs,
 * and what they have set up so far. Every figure comes from a query the app
 * already runs; there is no user number or join date to show because nothing
 * returns one.
 */
export function AccountIdCard(): JSX.Element {
    const { user } = useAuth();
    const namespaces = useMyNamespaces();
    const watches = useWatches();
    const sources = useListSources();
    const clusters = useMyClusters();
    const keys = useListAPIKeys();

    const watchedLabel = () => {
        const data = watches.data;
        if (data === undefined) return undefined;
        const n = data.data.length;
        return data.pagination.hasMore ? `${n}+ artifacts` : plural(n, "artifact");
    };

    const badges = () =>
        accountBadges({
            namespaceIds: (namespaces.data?.data ?? []).map((n) => n.id),
            sources: sources.data?.data ?? [],
            clusters: clusters.data?.data ?? [],
            apiKeyCount: keys.data?.keys?.length ?? 0,
        });

    return (
        <Show when={user()}>
            {(u) => (
                <section class="id-card" aria-label="Account">
                    <div class="id-card-who">
                        <span class="id-card-kind">Account</span>
                        <span class="id-card-name">{u().displayName}</span>
                        <span class="id-card-role">{u().role}</span>
                    </div>
                    <dl class="id-card-facts">
                        <Show when={namespaces.data}>
                            {(d) => (
                                <div>
                                    <dt>Namespaces</dt>
                                    <dd>{d().data.length.toLocaleString()}</dd>
                                </div>
                            )}
                        </Show>
                        <Show when={watchedLabel()}>
                            {(l) => (
                                <div>
                                    <dt>Watching</dt>
                                    <dd>{l()}</dd>
                                </div>
                            )}
                        </Show>
                    </dl>
                    <ul class="id-card-badges" aria-label="Badges">
                        <For each={badges()}>
                            {(b) => (
                                <li
                                    class={`id-badge id-badge-${b.shape}`}
                                    classList={{ "id-badge-earned": b.earned }}
                                    title={b.earned ? b.label : `${b.label}: ${b.how}`}
                                >
                                    <span class="id-badge-mark" aria-hidden="true" />
                                    <span class="id-badge-label">
                                        {b.label}
                                        <span class="sr-only">{b.earned ? " (earned)" : " (not yet)"}</span>
                                    </span>
                                </li>
                            )}
                        </For>
                    </ul>
                </section>
            )}
        </Show>
    );
}
