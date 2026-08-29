import type { Component, JSX } from "solid-js";
import { splitProps, Show } from "solid-js";
import { Dynamic } from "solid-js/web";

export type ButtonVariant = "primary" | "secondary" | "danger" | "ghost";
export type ButtonSize = "sm" | "md";

/**
 * variantClass maps a variant onto the CSS that already exists in index.css.
 *
 * `secondary` deliberately emits nothing: the bare `.btn` — surface background,
 * border, body text — *is* the secondary button, and there is no
 * `.btn-secondary` rule. (One call site writes that string today and has been
 * silently getting the default look, which is the same class of dead-class bug
 * as `tab-btn`; the Phase 2 sweep removes it.)
 */
function variantClass(variant: ButtonVariant): string {
    switch (variant) {
        case "primary":
            return " btn-primary";
        case "danger":
            return " btn-danger";
        case "ghost":
            return " btn-ghost";
        case "secondary":
            return "";
    }
}

interface Common {
    variant?: ButtonVariant;
    size?: ButtonSize;
    /** Renders a spinner and blocks interaction. Implies `disabled`. */
    loading?: boolean;
    disabled?: boolean;
    /**
     * The pressed state of a toggle. Styled by `.btn.active`, which is not
     * scoped to `.btn-group` — a lone toggle (Packages' "Vulnerable only")
     * is pressed in exactly the same sense as one half of a pair.
     */
    active?: boolean;
    class?: string;
    children?: JSX.Element;
}

type ButtonProps = Common &
    Omit<JSX.ButtonHTMLAttributes<HTMLButtonElement>, "class" | "disabled" | "children"> & {
        as?: "button";
    };

/**
 * `as` takes a component as well as the string `"a"` so that an in-app
 * destination can pass the router's `<A>`. A plain `<a href="/artifacts">`
 * inside an SPA is a full page reload, so "make this link look like a button"
 * must not silently cost client-side routing — which is exactly what would
 * happen if the only escape hatch were hand-writing `class="btn btn-sm"` on an
 * `<A>`, the drift this primitive exists to stop.
 */
type AnchorLike = Component<JSX.AnchorHTMLAttributes<HTMLAnchorElement> & { href: string }>;

type AnchorProps = Common &
    Omit<JSX.AnchorHTMLAttributes<HTMLAnchorElement>, "class" | "children"> & {
        as: "a" | AnchorLike;
    };

/**
 * Button is the one call site for the `.btn` family. It carries no visual
 * language of its own — every class it emits is a rule that already exists.
 *
 * `as="a"` exists because link-styled buttons are common here (a nav target that
 * should look like an action), and hand-rolling `class="btn btn-sm"` on an
 * anchor is how the class strings drifted in the first place.
 */
export function Button(props: ButtonProps | AnchorProps): JSX.Element {
    const [local, rest] = splitProps(props as Common & { as?: "button" | "a" | AnchorLike }, [
        "variant",
        "size",
        "loading",
        "disabled",
        "active",
        "class",
        "children",
        "as",
    ]);

    const disabled = () => local.disabled === true || local.loading === true;

    const cls = () => {
        let c = `btn${variantClass(local.variant ?? "secondary")}`;
        if (local.size === "sm") c += " btn-sm";
        if (local.active === true) c += " active";
        if (local.class !== undefined) c += ` ${local.class}`;
        return c;
    };

    return (
        <Dynamic
            component={local.as ?? "button"}
            class={cls()}
            // An anchor has no `disabled`; aria-disabled is what assistive tech
            // reads, and it is correct on both elements.
            aria-disabled={disabled() ? "true" : undefined}
            aria-busy={local.loading === true ? "true" : undefined}
            {...(local.as === undefined || local.as === "button" ? { disabled: disabled() } : {})}
            {...rest}
        >
            <Show when={local.loading === true}>
                <span class="btn-spinner" aria-hidden="true" />
            </Show>
            {local.children}
        </Dynamic>
    );
}
