import { A } from "@solidjs/router";
import { ExternalLink, Boxes, FileStack, Package, Scale, ShieldAlert } from "lucide-solid";
import { For, Show } from "solid-js";
import { Skeleton } from "~/components/Skeleton";
import { Button, StatBand, TypeBadge } from "~/components/ui";
import type { StatTile } from "~/components/ui";
import { useDashboardStats } from "~/api/queries";
import { HomeBand } from "~/pages/Dashboard/HomeBand";
import { HomeDiscovery } from "~/pages/HomeDiscovery";
import "./Home.css";

type Stats = NonNullable<ReturnType<typeof useDashboardStats>["data"]>;

const ICON = 14;

/**
 * The corpus in numbers. A tile links only where a list page exists to receive
 * the click — SBOMs are reachable only through their artifact, so that one is a
 * figure and nothing more.
 */
function statTiles(data: Stats): StatTile[] {
    return [
        {
            href: "/artifacts",
            icon: <Boxes size={ICON} />,
            head: "Artifacts",
            value: data.artifact_count.toLocaleString(),
            sub: "images, binaries and libraries",
        },
        {
            icon: <FileStack size={ICON} />,
            head: "SBOMs",
            value: data.sbom_count.toLocaleString(),
            sub: "one per image, arch and flavor",
        },
        {
            href: "/components",
            icon: <Package size={ICON} />,
            head: "Packages",
            value: data.package_count.toLocaleString(),
            // version_count is distinct *package* versions (db/queries/stats.sql
            // counts component_rollup.versions), not artifact versions — it
            // belongs here, not on the SBOM tile where it read as though the
            // catalog held more versions than SBOMs.
            sub: `${data.version_count.toLocaleString()} versions indexed`,
        },
        {
            href: "/licenses",
            icon: <Scale size={ICON} />,
            head: "Licenses",
            value: data.license_count.toLocaleString(),
            sub: "seen across the catalog",
        },
        {
            href: "/vulnerabilities",
            icon: <ShieldAlert size={ICON} />,
            head: "Vulnerabilities",
            value: data.vuln_count.toLocaleString(),
            sub: "matched to indexed packages",
        },
    ];
}

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
                            {/* The corpus in numbers, as the same StatBand every
                                detail page uses. It was a single mono-spaced run
                                of "38 artifacts · 107,868 packages · …" — legible
                                but inert, and it gave a stranger no way to act on
                                any of the four figures. Each tile that has a list
                                page behind it is now the link to it; SBOMs has no
                                list route, so it stays a plain tile rather than
                                pretending to be clickable (ocidex-ag4q.42). */}
                            <StatBand class="landing-band" tiles={statTiles(data())} />
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
