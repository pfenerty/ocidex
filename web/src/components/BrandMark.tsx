/**
 * The OCIDex mark, inline so it takes the theme's tokens: the body is currentColor and
 * the lens-LED takes the brand token via .brand-mark-led in index.css, the only place
 * brand red lives (ocidex-iz0r). The geometry is copied from web/public/brand/mark.svg;
 * brandAssets.test.ts keeps the two in step. Decorative unless given a title, since a
 * wordmark almost always sits beside it.
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
                d="M10.5 3h11A7.5 7.5 0 0 1 29 10.5v11a7.5 7.5 0 0 1-7.5 7.5h-11A7.5 7.5 0 0 1 3 21.5v-11A7.5 7.5 0 0 1 10.5 3zM11.2 6.5a4.7 4.7 0 1 0 0 9.4 4.7 4.7 0 1 0 0-9.4zM9.75 18.2h12.5a1.35 1.35 0 0 1 0 2.7H9.75a1.35 1.35 0 0 1 0-2.7zM9.75 22.6h6.7a1.35 1.35 0 0 1 0 2.7h-6.7a1.35 1.35 0 0 1 0-2.7z"
            />
            <circle class="brand-mark-led" cx="11.2" cy="11.2" r="3.1" />
        </svg>
    );
}
