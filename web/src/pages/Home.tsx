import { A } from "@solidjs/router";
import { Search } from "lucide-solid";
import { For, Show } from "solid-js";
import { openCommandPalette, isAppleShortcut } from "~/components/CommandPalette";
import { Skeleton } from "~/components/Skeleton";
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
        <footer class="home-facts">
            <For each={facts(props.data)}>
                {(f) => {
                    const inner = (
                        <>
                            <span class="home-fact-value">{f.value}</span> {f.label}
                        </>
                    );
                    return f.href !== undefined ? (
                        <A href={f.href} class="home-fact" title={f.title}>
                            {inner}
                        </A>
                    ) : (
                        <span class="home-fact" title={f.title}>
                            {inner}
                        </span>
                    );
                }}
            </For>
        </footer>
    );
}

/**
 * Home is for someone who has never heard of OCIDex: one line on what it is,
 * search, then the images and packages they already know, in tables. The
 * catalog totals close the page rather than open it.
 */
export default function Home() {
    const stats = useDashboardStats();

    return (
        <div class="home">
            <section class="home-intro">
                <h1 class="home-title">What's inside the container images you already pull</h1>
                <p class="home-pitch">
                    OCIDex reads the SBOM of every published tag: each package, its license, the CVEs known against it,
                    and what changed from the tag before.
                </p>
                {/* The same palette as the sidebar's search, not a second one. */}
                <button type="button" class="home-search" onClick={openCommandPalette}>
                    <Search size={16} />
                    <span>Look up an image, package or CVE</span>
                    <kbd>{isAppleShortcut() ? "\u2318K" : "Ctrl K"}</kbd>
                </button>
            </section>

            {/* Signed-in band; renders nothing when signed out. */}
            <HomeBand />

            <HomeDiscovery />

            {/* Stats have three states and all three are visible: a failure
                must not read as an empty catalog, and a warming payload carries
                zero placeholders rather than counts. */}
            <Show
                when={stats.data && !stats.data.warming ? stats.data : undefined}
                fallback={
                    <div class="home-facts">
                        <Show when={stats.isError} fallback={<Skeleton width="24rem" height="1em" />}>
                            <span class="home-muted">Catalog stats are unavailable.</span>
                        </Show>
                    </div>
                }
            >
                {(data) => <FactStrip data={data()} />}
            </Show>
        </div>
    );
}
