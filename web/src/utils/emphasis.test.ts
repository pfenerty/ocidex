import { describe, it, expect } from "vitest";
import { roleEmphasis, type Membership } from "./emphasis";

const m = (...roles: string[]): Membership[] =>
    roles.map((role, i) => ({ namespace_id: `n${String(i)}`, role }));

describe("roleEmphasis", () => {
    const cases: [string, Membership[] | undefined, string][] = [
        ["no memberships is balanced", [], "balanced"],
        ["an older server that omits the field is balanced", undefined, "balanced"],
        ["all security", m("security", "security"), "security"],
        ["all developer", m("developer"), "developer"],
        ["mostly security", m("security", "security", "developer"), "security"],
        ["mostly developer", m("developer", "developer", "security"), "developer"],
        ["an even split is balanced", m("security", "developer"), "balanced"],
        ["viewer-only is balanced", m("viewer", "viewer"), "balanced"],
        // Answerable for a namespace beats the count: an owner is responsible
        // for both halves of the page even where the rest of their
        // memberships are one-sided.
        ["an owner anywhere is balanced", m("security", "security", "owner"), "balanced"],
        ["a maintainer anywhere is balanced", m("developer", "maintainer"), "balanced"],
        // A role string this build does not know grants nothing server-side
        // and must not tip the layout either.
        ["an unknown role counts for neither", m("auditor", "security"), "security"],
    ];

    for (const [name, memberships, want] of cases) {
        it(name, () => {
            expect(roleEmphasis(memberships)).toBe(want);
        });
    }
});
