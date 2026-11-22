import { A } from "@solidjs/router";
import { ExternalLink, Search } from "lucide-solid";
import { For, Show } from "solid-js";
import { openCommandPalette, isAppleShortcut } from "~/components/CommandPalette";
import { Skeleton } from "~/components/Skeleton";
import { Button, TypeBadge } from "~/components/ui";
import { useDashboardStats } from "~/api/queries";
import { HomeBand } from "~/pages/Dashboard/HomeBand";
import { HomeDiscovery } from "~/pages/HomeDiscovery";
import "./Home.css";

type Stats = NonNullable<ReturnType<typeof useDashboardStats>["data"]>;

/** One figure in the stat strip; `href` only where a list page receives it. */
interface Fact {
    href?: string;
    value: string;
    label: string;
    /** Hover text, where the label alone would claim more than the figure counts. */
    title?: string;
}

/**
 * The corpus in numbers. A figure links only where a list page exists to
 * receive the click: SBOMs are reachable only through their artifact.
 */
function facts(data: Stats): Fact[] {
    return [
        { href: "/artifacts", value: data.artifactCount.toLocaleString(), label: "artifacts" },
        { value: data.sbomCount.toLocaleString(), label: "SBOMs" },
        // versionCount is distinct *package* versions, not artifact versions.
        { href: "/components", value: data.packageCount.toLocaleString(), label: "packages" },
        { href: "/licenses", value: data.licenseCount.toLocaleString(), label: "licenses" },
        // Every advisory any indexed version carries, superseded ones included:
        // counting only latest versions would need a live join over every
        // artifact's SBOM, which is what the rollup exists to avoid. So the
        // label says "known", and the hover says what that covers.
        {
            href: "/vulnerabilities",
            value: data.vulnCount.toLocaleString(),
            label: "known vulnerabilities",
            title: "Advisories found in any indexed version, not only the latest",
        },
    ];
}

function FactStrip(props: { data: Stats }) {
    return (
        <div class="landing-facts">
            <For each={facts(props.data)}>
                {(f) => {
                    const inner = (
                        <>
                            <span class="landing-fact-value">{f.value}</span>
                            <span class="landing-fact-label">{f.label}</span>
                        </>
                    );
                    return f.href !== undefined ? (
                        <A href={f.href} class="landing-fact" title={f.title}>
                            {inner}
                        </A>
                    ) : (
                        <div class="landing-fact" title={f.title}>{inner}</div>
                    );
                }}
            </For>
        </div>
    );
}

export default function Home() {
    const stats = useDashboardStats();

    return (
        <div class="landing">
            <section class="landing-hero">
                <h1 class="brand landing-title">What changed since the last tag.</h1>
                {/* The line stays short; this does the explaining, with the
                    real count once stats arrive. */}
                <p class="landing-pitch">
                    SBOMs for{" "}
                    {stats.data && !stats.data.warming
                        ? `${stats.data.artifactCount.toLocaleString()} images, binaries and libraries`
                        : "every image, binary and library you ship"}
                    , read down to each package and compared version to version.
                </p>
                {/* The palette is the fastest way into the catalog, and the
                    sidebar's button is easy to miss on a first visit. This is
                    the same palette, not a second search. */}
                <button type="button" class="landing-search" onClick={openCommandPalette}>
                    <Search size={16} />
                    <span>Search images, packages and CVEs</span>
                    <kbd>{isAppleShortcut() ? "\u2318K" : "Ctrl K"}</kbd>
                </button>
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
                            <FactStrip data={data()} />
                            {/* The breakdown counts the same artifact set as
                                artifactCount above, so the chips always sum to
                                it. The field is nullable in the generated spec —
                                an empty catalog has no chips to show at all. */}
                            <Show when={data().artifactTypes?.length}>
                                <div class="landing-types">
                                    <For each={data().artifactTypes}>
                                        {(t) => (
                                            <A
                                                href={`/artifacts?type=${encodeURIComponent(t.type)}`}
                                                class="landing-type"
                                            >
                                                <TypeBadge type={t.type} />
                                                <span class="landing-type-count">
                                                    {t.artifactCount.toLocaleString()}
                                                </span>
                                            </A>
                                        )}
                                    </For>
                                </div>
                            </Show>
                        </>
                    )}
                </Show>
                {/* Three things to do, phrased as verbs. The tiles above say how
                    much is in the index; these say what you can do with it. A
                    stranger who reads only the top of this page should leave it
                    with a destination. */}
                <div class="landing-ctas">
                    <Button as={A} href="/artifacts" variant="primary">
                        Browse artifacts
                    </Button>
                    <Button as={A} href="/components">
                        Search components
                    </Button>
                    <Button as={A} href="/vulnerabilities">
                        Review vulnerabilities
                    </Button>
                    <Button
                        as="a"
                        href="https://github.com/pfenerty/ocidex"
                        target="_blank"
                        rel="noreferrer noopener"
                    >
                        <ExternalLink size={14} />
                        GitHub
                    </Button>
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
