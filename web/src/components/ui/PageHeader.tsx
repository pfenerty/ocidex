import { formatEntryNumber } from "~/utils/format";
import type { JSX } from "solid-js";
import { Show, onCleanup, onMount } from "solid-js";

/** APP_TITLE is the document title's suffix, and the whole title off a page header. */
export const APP_TITLE = "OCIDex";

/**
 * documentTitleFor builds "<page> · OCIDex" from a header's text, collapsing
 * the whitespace JSX leaves between inline pieces.
 */
export function documentTitleFor(text: string): string {
    const page = text.replace(/\s+/g, " ").trim();
    return page === "" ? APP_TITLE : `${page} · ${APP_TITLE}`;
}

/**
 * PageHeader emits the `.page-header` / `.page-header-row` structure that 19
 * page files hand-repeat today. It adds no CSS: the markup is exactly what
 * `components/Layout.css` already styles.
 *
 * The nesting is load-bearing. `.page-header-row` is
 * `justify-content: space-between`, so the title and subtitle must be wrapped
 * together in one child — emitting `h2`, `p` and `actions` as three siblings
 * spreads them across the row instead of pinning actions to the right.
 *
 * The subtitle carries no class: `.page-header p` already resolves to
 * `--color-text-muted`, so the `text-muted` some call sites add is a no-op.
 */
/**
 * EntryLine is the Dex-entry eyebrow every detail page opens with (ocidex-iz0r.6):
 * the kind of thing, then its short id, the way a Dex entry opens with its number.
 * Chips (type, status) follow it as siblings in the `eyebrow` slot.
 */
export function EntryLine(props: { kind: string; id?: string; number?: number }): JSX.Element {
    return (
        <span class="entry-line">
            {props.kind}
            <Show
                when={props.number}
                fallback={
                    <Show when={props.id !== undefined && props.id !== ""}>
                        {" № "}
                        {props.id?.slice(0, 8)}
                    </Show>
                }
            >
                {(n) => <> {formatEntryNumber(n())}</>}
            </Show>
        </span>
    );
}

/**
 * TitleWithPrefix mutes everything up to the last "/" of a slash-path name, so
 * "ghcr.io/pfenerty/ocidex-api" reads as its registry path plus its name.
 */
export function TitleWithPrefix(props: { name: string }): JSX.Element {
    const cut = () => props.name.lastIndexOf("/") + 1;
    return (
        <>
            <Show when={cut() > 0}>
                <span class="page-header-prefix">{props.name.slice(0, cut())}</span>
            </Show>
            {props.name.slice(cut())}
        </>
    );
}

export function PageHeader(props: {
    /**
     * Above the title: an <EntryLine> plus any type or status chips. Detail
     * pages set it; list pages do not.
     */
    eyebrow?: JSX.Element;
    title: JSX.Element;
    subtitle?: JSX.Element;
    /** Right-hand slot. Usually a `.btn-group`. */
    actions?: JSX.Element;
    /**
     * Rendered above the title. Detail pages currently emit their own
     * `.breadcrumb` div just before the header; this is where that moves in the
     * Phase 4 breadcrumb story.
     */
    breadcrumb?: JSX.Element;
    /**
     * Extra content in the left column, below the subtitle — SBOMDetail's
     * copyable digest, VulnerabilityDetail's alias line.
     *
     * It exists because `subtitle` is wrapped in a `<p>`, and `.page-header p`
     * is what carries the muted colour and the 0.25rem top margin. A block
     * element passed as `subtitle` would be auto-closed out of that paragraph
     * by the parser and lose both. A caller with block content puts it here and
     * leaves `subtitle` unset.
     */
    meta?: JSX.Element;
    /**
     * Full-width content below the row, still inside `.page-header` so it sits
     * above the header's bottom margin — ClusterDetail's `<DetailGrid>`.
     */
    footer?: JSX.Element;
}): JSX.Element {
    // Every page was titled "OCIDex", so tabs, history and bookmarks could not
    // tell an artifact from a CVE (ocidex-nps9.16). The header's own text is the
    // page's name, so the document title follows it — observed rather than read
    // once, because most titles fill in when their query resolves.
    let heading: HTMLHeadingElement | undefined;
    onMount(() => {
        const el = heading;
        if (el === undefined) return;
        const sync = () => {
            document.title = documentTitleFor(el.textContent);
        };
        sync();
        const observer = new MutationObserver(sync);
        observer.observe(el, { childList: true, subtree: true, characterData: true });
        onCleanup(() => {
            observer.disconnect();
            document.title = APP_TITLE;
        });
    });

    return (
        <div class="page-header">
            <Show when={props.breadcrumb !== undefined}>
                <div class="breadcrumb">{props.breadcrumb}</div>
            </Show>
            <div class="page-header-row">
                <div>
                    <Show when={props.eyebrow !== undefined}>
                        <div class="page-header-eyebrow">{props.eyebrow}</div>
                    </Show>
                    <h2 ref={heading}>{props.title}</h2>
                    <Show when={props.subtitle !== undefined}>
                        <p>{props.subtitle}</p>
                    </Show>
                    {props.meta}
                </div>
                <Show when={props.actions !== undefined}>{props.actions}</Show>
            </div>
            {props.footer}
        </div>
    );
}
