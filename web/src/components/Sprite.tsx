import "./Sprite.css";
import { For, Show, createUniqueId, type JSX } from "solid-js";
import { sameVariantAsNewest, type SeverityPoint } from "~/utils/versionDelta";

const MAX_BARS = 6;
const BASE = 23;
const TOP = 3;

/**
 * An artifact's sprite: the mark redrawn from its own history. One bar per
 * version, oldest left, for up to the six newest versions of the newest
 * version's variant. A hatched block above a bar is what that version fixed;
 * an amber block is what it added. A trend reads before anything is opened:
 * stepping down, stepping up or flat.
 *
 * Versions with no findings record are left out rather than drawn as zero,
 * since "no findings" and "never scanned" look the same in the data.
 */
export function Sprite(props: {
    points: SeverityPoint[];
    size?: number;
    class?: string;
    /**
     * Draw the newest bar in the critical colour when it has critical
     * findings. Each sprite scales to its own maximum, so a row of them reads
     * as identical glyphs; the tint says which ones carry criticals now.
     */
    tintNewest?: boolean;
}): JSX.Element {
    const hatchId = `sprite-hatch-${createUniqueId()}`;
    const bars = () => sameVariantAsNewest(props.points).slice(0, MAX_BARS).reverse();
    const max = () => Math.max(1, ...bars().map((p) => p.critical ?? 0));
    const y = (v: number) => BASE - (v / max()) * (BASE - TOP);
    // A floor so a zero still shows as a sliver on the baseline.
    const floor = (v: number) => Math.max(v, max() * 0.04);
    const gap = 1.2;
    // Capped, so one or two versions draw as bars rather than a filled square,
    // and centred in the box.
    const width = () => Math.min(6, (26 - 4 - gap * (bars().length - 1)) / Math.max(bars().length, 1));
    const start = () => (26 - (bars().length * width() + gap * (bars().length - 1))) / 2;
    const size = () => props.size ?? 22;
    const label = () =>
        bars().length === 0
            ? "No version history"
            : `Critical findings, oldest to newest: ${bars()
                  .map((p) => `${p.versionKey} ${p.critical ?? 0}`)
                  .join(", ")}`;

    return (
        <span class={props.class === undefined ? "sprite" : `sprite ${props.class}`} title={label()}>
            <svg width={size()} height={size()} viewBox="0 0 26 26" role="img" aria-label={label()}>
                <defs>
                    <pattern id={hatchId} width="2.4" height="2.4" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
                        <line class="sprite-hatch-line" x1="0" y1="0" x2="0" y2="2.4" />
                    </pattern>
                </defs>
                <Show when={bars().length > 0} fallback={<line class="sprite-empty" x1="4" y1={BASE} x2="22" y2={BASE} />}>
                    <For each={bars()}>
                        {(p, i) => {
                            const cur = () => p.critical ?? 0;
                            const prev = () => (i() > 0 ? bars()[i() - 1].critical ?? 0 : cur());
                            const x = () => start() + i() * (width() + gap);
                            const newestCritical = () =>
                                props.tintNewest === true && i() === bars().length - 1 && cur() > 0;
                            return (
                                <g>
                                    <rect
                                        class="sprite-bar"
                                        classList={{ "sprite-bar-critical": newestCritical() }}
                                        x={x()} y={y(floor(cur()))} width={width()} height={BASE - y(floor(cur()))} />
                                    <Show when={prev() > cur()}>
                                        <rect
                                            class="sprite-fixed"
                                            x={x() + 0.35}
                                            y={y(prev()) + 0.35}
                                            width={Math.max(0, width() - 0.7)}
                                            height={Math.max(0, y(floor(cur())) - y(prev()) - 0.35)}
                                            fill={`url(#${hatchId})`}
                                        />
                                    </Show>
                                    <Show when={cur() > prev()}>
                                        <rect class="sprite-added" x={x()} y={y(cur())} width={width()} height={y(prev()) - y(cur())} />
                                    </Show>
                                </g>
                            );
                        }}
                    </For>
                </Show>
            </svg>
        </span>
    );
}
