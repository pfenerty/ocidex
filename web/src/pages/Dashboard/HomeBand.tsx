import { Show, type JSX } from "solid-js";
import { A } from "@solidjs/router";
import { LayoutDashboard } from "lucide-solid";
import { useAuth } from "~/context/auth";
import { useMyNamespaces, useMyDriftFeed, useWatches } from "~/api/queries";
import { plural } from "~/utils/format";
import "./Dashboard.css";

/**
 * HomeBand is the signed-in strip on the public landing page: enough of the
 * workspace to know whether it needs attention, and a way into it.
 *
 * It sits *alongside* the discovery cards rather than replacing them — a signed-in
 * user still browses the catalog. It is also the only place the two views meet,
 * so it deliberately shows counts, not rows: anything more would be a second
 * dashboard to keep in sync with the first.
 *
 * Only mount this when there is a user. Its three queries all hit /users/me/*,
 * which answer 401 to a signed-out visitor, and a landing page must not open
 * with three failed requests.
 */
export function HomeBand(): JSX.Element {
    const { user } = useAuth();
    const namespaces = useMyNamespaces();
    const watches = useWatches();
    const drift = useMyDriftFeed();

    return (
        <Show when={user()}>
            {(u) => (
                <section class="home-band">
                    <span class="home-band-greeting">Welcome back, {u().github_username}</span>
                    {/* Each figure appears only once its query has answered.
                        A count that reads 0 while still loading is worse than
                        no count: it is a wrong answer rendered confidently. */}
                    <span class="home-band-stats">
                        <Show when={namespaces.data}>
                            {(d) => <span>{plural(d().data.length, "namespace")}</span>}
                        </Show>
                        <Show when={watches.data}>
                            {(d) => (
                                <>
                                    <span class="home-band-sep">·</span>
                                    <span>{plural(d().data.length, "watched artifact")}</span>
                                </>
                            )}
                        </Show>
                        {/* Drift shows only when there is some — a permanent
                            "0 drift events" trains people to stop reading the
                            band, and this is the figure worth interrupting for. */}
                        <Show when={(drift.data?.data.length ?? 0) > 0}>
                            <span class="home-band-sep">·</span>
                            <span class="home-band-alert">
                                {plural(drift.data?.data.length ?? 0, "drift event")}
                            </span>
                        </Show>
                    </span>
                    <A href="/dashboard" class="btn btn-sm home-band-cta">
                        <LayoutDashboard size={14} />
                        Open workspace
                    </A>
                </section>
            )}
        </Show>
    );
}
