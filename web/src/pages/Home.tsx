import { A } from "@solidjs/router";
import { Package, Layers, ShieldCheck, ArrowUpDown, ExternalLink } from "lucide-solid";
import { Show } from "solid-js";
import { useDashboardStats } from "~/api/queries";

export default function Home() {
    const stats = useDashboardStats();

    return (
        <div class="landing">
            <section class="landing-hero">
                <h1 class="brand landing-title">
                    OCI<span>Dex</span>
                </h1>
                <p class="landing-tagline">The supply-chain catalog for OCI artifacts.</p>
                <p class="landing-pitch">
                    Ingest SBOMs, track packages across versions, and understand your license
                    exposure — all from a single searchable index. Know what's in your containers
                    before your next incident does.
                </p>
                <Show when={stats.data}>
                    {(data) => (
                        <div class="landing-stats">
                            <span>{data().artifact_count.toLocaleString()} artifacts</span>
                            <span class="landing-stats-sep">·</span>
                            <span>{data().package_count.toLocaleString()} packages</span>
                            <span class="landing-stats-sep">·</span>
                            <span>{data().license_count.toLocaleString()} licenses</span>
                        </div>
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
                            Browse tracked OCI images and Helm charts, each with full SBOM history
                            and version timeline.
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
                </div>
            </section>
        </div>
    );
}
