import { A } from "@solidjs/router";
import { ExternalLink } from "lucide-solid";
import { For, Show } from "solid-js";
import { Skeleton } from "~/components/Skeleton";
import { TypeBadge } from "~/components/ui";
import { useDashboardStats } from "~/api/queries";
import { HomeBand } from "~/pages/Dashboard/HomeBand";
import { HomeDiscovery } from "~/pages/HomeDiscovery";
import "./Home.css";

export default function Home() {
    const stats = useDashboardStats();

    return (
        <div class="landing">
            <section class="landing-hero">
                <h1 class="brand landing-title">
                    OCI<span>Dex</span>
                </h1>
                <p class="landing-tagline">The supply-chain catalog for the software you ship.</p>
                <p class="landing-pitch">
                    Ingest SBOMs, track packages across versions, and understand your license
                    exposure — all from a single searchable index. Know what's inside every
                    image, binary and library you ship before your next incident does.
                </p>
                {/* Stats have three states and all three are visible: an
                    unadorned <Show> rendered a failure as silence, which is
                    indistinguishable from a catalog that is simply empty.
                    A `warming` payload carries zero placeholders rather than
                    real counts, so it belongs in the loading state too — the
                    query keeps polling until a computed snapshot lands. */}
                <Show
                    when={stats.data && !stats.data.warming ? stats.data : undefined}
                    fallback={
                        <div class="landing-stats">
                            <Show
                                when={stats.isError}
                                fallback={<Skeleton width="24rem" height="1em" />}
                            >
                                <span class="text-muted">Catalog stats are unavailable.</span>
                            </Show>
                        </div>
                    }
                >
                    {(data) => (
                        <>
                            <div class="landing-stats">
                                <span>{data().artifact_count.toLocaleString()} artifacts</span>
                                <span class="landing-stats-sep">·</span>
                                <span>{data().package_count.toLocaleString()} packages</span>
                                <span class="landing-stats-sep">·</span>
                                <span>{data().license_count.toLocaleString()} licenses</span>
                                <span class="landing-stats-sep">·</span>
                                <span>{data().vuln_count.toLocaleString()} vulnerabilities</span>
                            </div>
                            {/* The breakdown counts the same artifact set as
                                artifact_count above, so the chips always sum to
                                it. The field is nullable in the generated spec —
                                an empty catalog has no chips to show at all. */}
                            <Show when={data().artifact_types?.length}>
                                <div class="landing-types">
                                    <For each={data().artifact_types}>
                                        {(t) => (
                                            <A
                                                href={`/artifacts?type=${encodeURIComponent(t.type)}`}
                                                class="landing-type"
                                            >
                                                <TypeBadge type={t.type} />
                                                <span class="landing-type-count">
                                                    {t.artifact_count.toLocaleString()}
                                                </span>
                                            </A>
                                        )}
                                    </For>
                                </div>
                            </Show>
                        </>
                    )}
                </Show>
                <div class="landing-ctas">
                    <A href="/artifacts" class="btn btn-primary">
                        Browse Artifacts
                    </A>
                    <a
                        href="https://github.com/pfenerty/ocidex"
                        class="btn"
                        target="_blank"
                        rel="noreferrer noopener"
                    >
                        <ExternalLink size={14} />
                        GitHub
                    </a>
                </div>
            </section>

            {/* Personalized band for signed-in users (ocidex-998g.5). It renders
                nothing when signed out, which is why it sits between the hero and
                the discovery cards rather than inside either. */}
            <HomeBand />

            {/* Live catalog content, not a description of it (ocidex-q1z7.3).
                The five static feature cards this replaces said the same thing
                to a full catalog and an empty one, so they told a first-time
                visitor nothing about whether the index was worth searching.
                Section navigation now lives on each panel's "see all" link. */}
            <HomeDiscovery />
        </div>
    );
}
