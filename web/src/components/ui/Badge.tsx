import type { JSX } from "solid-js";

export type BadgeVariant = "default" | "primary" | "success" | "warning" | "danger";

function variantSuffix(variant: BadgeVariant | undefined): string {
    return variant && variant !== "default" ? ` badge-${variant}` : "";
}

export function Badge(props: { variant?: BadgeVariant; title?: string; children: JSX.Element }) {
    return <span class={`badge${variantSuffix(props.variant)}`} title={props.title}>{props.children}</span>;
}

export function StatusPill(props: { variant?: BadgeVariant; title?: string; children: JSX.Element }) {
    return <span class={`badge badge-sm${variantSuffix(props.variant)}`} title={props.title}>{props.children}</span>;
}
