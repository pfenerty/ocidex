import { A } from "@solidjs/router";
import { Package, Layers, ShieldCheck, ArrowUpDown, ExternalLink, ShieldAlert } from "lucide-solid";
import { For, Show } from "solid-js";
import { Skeleton } from "~/components/Skeleton";
import { TypeBadge } from "~/components/ui";
import { useDashboardStats } from "~/api/queries";
import { HomeBand } from "~/pages/Dashboard/HomeBand";
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

            <section class="landing-features">
                <div class="landing-features-grid">
                    <A href="/artifacts" class="card entry-card landing-feature-card">
                        <div class="landing-card-header">
                            <span class="entry-number">#001</span>
                            <span class="badge badge-primary">artifacts</span>
                        </div>
                        <Package size={28} class="landing-card-icon" />
                        <h3 class="landing-card-title">Artifacts</h3>
                        <p class="landing-card-desc">
                            Browse every tracked artifact — container images, binaries, libraries,
                            applications — each with full SBOM history and version timeline.
                        </p>
                    </A>

                    <A href="/components" class="card entry-card landing-feature-card">
                        <div class="landing-card-header">
                            <span class="entry-number">#002</span>
                            <span class="badge">components</span>
                        </div>
                        <Layers size={28} class="landing-card-icon" />
                        <h3 class="landing-card-title">Components</h3>
                        <p class="landing-card-desc">
                            Search packages across your entire catalog — find where a dependency
                            appears and how many versions carry it.
                        </p>
                    </A>

                    <A href="/licenses" class="card entry-card landing-feature-card">
                        <div class="landing-card-header">
                            <span class="entry-number">#003</span>
                            <span class="badge badge-success">licenses</span>
                        </div>
                        <ShieldCheck size={28} class="landing-card-icon" />
                        <h3 class="landing-card-title">Licenses</h3>
                        <p class="landing-card-desc">
                            Understand your compliance posture — see every license in use and which
                            components carry it.
                        </p>
                    </A>

                    <A href="/diff" class="card entry-card landing-feature-card">
                        <div class="landing-card-header">
                            <span class="entry-number">#004</span>
                            <span class="badge">compare</span>
                        </div>
                        <ArrowUpDown size={28} class="landing-card-icon" />
                        <h3 class="landing-card-title">Compare</h3>
                        <p class="landing-card-desc">
                            Diff two SBOMs side-by-side — understand what changed between builds in
                            seconds.
                        </p>
                    </A>

                    <A href="/vulnerabilities" class="card entry-card landing-feature-card">
                        <div class="landing-card-header">
                            <span class="entry-number">#005</span>
                            <span class="badge badge-danger">vulnerabilities</span>
                        </div>
                        <ShieldAlert size={28} class="landing-card-icon" />
                        <h3 class="landing-card-title">Vulnerabilities</h3>
                        <p class="landing-card-desc">
                            See which CVEs affect your catalog — ranked by how many artifacts carry
                            them.
                        </p>
                    </A>
                </div>
            </section>
        </div>
    );
}
