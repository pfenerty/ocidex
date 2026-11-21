/**
 * The OCIDex mark, inline so it takes the theme's text colour (currentColor).
 * Three bars stepping down, each a version's critical count, with the part the
 * release fixed drawn as an open outline above it: the artifact page's version
 * chart, shrunk. The geometry is copied from web/public/brand/mark.svg;
 * brandAssets.test.ts keeps the two in step. Decorative unless given a title,
 * since a wordmark almost always sits beside it.
 */
export function BrandMark(props: { size?: number; class?: string; title?: string }) {
    const size = () => props.size ?? 24;
    const labelled = () => props.title !== undefined && props.title !== "";
    return (
        <svg
            class={props.class === undefined ? "brand-mark" : `brand-mark ${props.class}`}
            width={size()}
            height={size()}
            viewBox="0 0 32 32"
            role={labelled() ? "img" : undefined}
            aria-label={labelled() ? props.title : undefined}
            aria-hidden={labelled() ? undefined : "true"}
        >
            <path
                fill="currentColor"
                fill-rule="evenodd"
                d="M3 4h7v24H3zM12.5 16h7v12h-7zM22 22h7v6h-7zM12.5 8h7v8h-7zM14.5 10v6h3v-6zM22 14h7v8h-7zM24 16v6h3v-6z"
            />
        </svg>
    );
}
