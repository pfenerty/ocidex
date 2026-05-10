import { createSignal, Show, For } from "solid-js";
import { A } from "@solidjs/router";
import type { ChangelogEntryData } from "~/utils/diff";
import { changelogRefLabel } from "~/utils/diff";
import { relativeDate } from "~/utils/format";
import { DiffPairView } from "~/components/DiffPairView";

// DiffEntryCard wraps a single SBOM-pair comparison in a collapsible card.
// The header (from→to + summary badges) is always rendered cheaply; the body
// (DiffPairView, which fires a useDiffTree query) is only mounted when the
// card is expanded. This lets the changelog page render a long timeline
// without firing N parallel queries upfront.
export function DiffEntryCard(props: {
    entry: ChangelogEntryData;
    viewMode: "tree" | "list";
    defaultExpanded: boolean;
}) {
    const [expanded, setExpanded] = createSignal(props.defaultExpanded);

    const summary = () => props.entry.summary;
    const kindDefs = [
        { count: () => summary().added,      cls: "badge-primary",  fmt: (n: number) => `+${n} added` },
        { count: () => summary().removed,    cls: "badge-warning",  fmt: (n: number) => `-${n} removed` },
        { count: () => summary().upgraded,   cls: "badge-primary",  fmt: (n: number) => `↑${n} upgraded` },
        { count: () => summary().downgraded, cls: "badge-warning",  fmt: (n: number) => `↓${n} downgraded` },
    ];

    return (
        <div class="card mb-4" style={{ "padding": "0", overflow: "hidden" }}>
            <div
                role="button"
                tabindex="0"
                aria-expanded={expanded()}
                onClick={() => setExpanded(!expanded())}
                onKeyDown={(e: KeyboardEvent) => {
                    if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setExpanded(!expanded());
                    }
                }}
                style={{
                    display: "flex",
                    "align-items": "center",
                    "justify-content": "space-between",
                    gap: "0.75rem",
                    padding: "0.75rem 1rem",
                    cursor: "pointer",
                    "user-select": "none",
                    "border-bottom": expanded() ? "1px solid var(--color-border)" : "none",
                    "flex-wrap": "wrap",
                }}
            >
                <div style={{ display: "flex", "align-items": "center", gap: "0.5rem", "min-width": "0", "flex-wrap": "wrap" }}>
                    <span
                        style={{
                            width: "1rem",
                            "text-align": "center",
                            color: "var(--color-text-dim)",
                            "font-size": "0.7rem",
                            "flex-shrink": "0",
                            transition: "transform 0.15s",
                            transform: expanded() ? "rotate(90deg)" : "rotate(0deg)",
                        }}
                    >
                        ▸
                    </span>
                    <div class="text-sm" onClick={(e: MouseEvent) => e.stopPropagation()}>
                        <A href={`/sboms/${props.entry.from.id}`} class="font-mono">
                            {changelogRefLabel(props.entry.from)}
                        </A>
                        {" → "}
                        <A href={`/sboms/${props.entry.to.id}`} class="font-mono">
                            {changelogRefLabel(props.entry.to)}
                        </A>
                        <span class="text-muted">
                            {" "}
                            ({relativeDate(props.entry.to.buildDate ?? props.entry.to.createdAt)})
                        </span>
                    </div>
                </div>
                <div class="changelog-summary" style={{ display: "flex", gap: "0.35rem", "flex-wrap": "wrap" }}>
                    <For each={kindDefs}>
                        {(k) => (
                            <Show when={k.count() > 0}>
                                <span class={`badge ${k.cls}`}>{k.fmt(k.count())}</span>
                            </Show>
                        )}
                    </For>
                </div>
            </div>
            <Show when={expanded()}>
                <div style={{ padding: "0.75rem 1rem" }}>
                    <DiffPairView
                        fromId={props.entry.from.id}
                        toId={props.entry.to.id}
                        viewMode={props.viewMode}
                        hideHeader={true}
                    />
                </div>
            </Show>
        </div>
    );
}
