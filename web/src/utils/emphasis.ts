/**
 * Role emphasis (ocidex-y0hg.9).
 *
 * A security engineer and a developer read the same rows off the same
 * endpoints and want different things off the top of the page. This turns the
 * caller's namespace memberships into one of three emphases, which the
 * Workspace uses to order its panels and the sidebar uses to accent a couple
 * of links.
 *
 * It orders and accents; it never filters. Nothing the caller is allowed to
 * see is hidden by an emphasis — hiding readable data behind a role is a
 * usability decision wearing a security decision's clothes, and it makes the
 * page lie about what the caller has access to. Authorization is decided
 * server-side on every request (ADR-046); this is layout.
 */

/** One membership as /users/me reports it. */
export interface Membership {
    namespace_id: string;
    role: string;
}

export type Emphasis = "security" | "developer" | "balanced";

/**
 * roleEmphasis picks the emphasis for a set of memberships.
 *
 * Anyone answerable for a namespace — an owner or a maintainer — gets
 * "balanced": they are responsible for both halves of the page, and demoting
 * either half for them would be wrong regardless of what else they hold. Below
 * that, whichever of security/developer they hold more of wins; a tie, a
 * viewer-only account, and no memberships at all are all "balanced" too.
 *
 * The caller's *global* role is deliberately not an input. An admin is not a
 * persona, and an installation with one admin who is also a namespace's
 * security contact should still get the security emphasis.
 */
export function roleEmphasis(memberships: readonly Membership[] | undefined): Emphasis {
    if (!memberships) return "balanced";

    let security = 0;
    let developer = 0;
    for (const m of memberships) {
        if (m.role === "owner" || m.role === "maintainer") return "balanced";
        if (m.role === "security") security++;
        else if (m.role === "developer") developer++;
    }

    if (security > developer) return "security";
    if (developer > security) return "developer";
    return "balanced";
}
