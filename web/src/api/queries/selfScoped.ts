/**
 * Options shared by every hook that reads a /api/v1/users/me/* endpoint.
 *
 * These endpoints answer 401 to a signed-out visitor. That used to be
 * survivable only because the API client hard-navigated to /login on any 401 —
 * which is to say the failure was hidden by a worse bug (ocidex-ag4q.1). With
 * that gone, a self-scoped query mounted on a public page produces a real,
 * visible failure, so the mount itself has to be conditional.
 *
 * `enabled` is an accessor, not a boolean, because the auth resource resolves
 * after first paint: passing `user() !== undefined` by value would capture
 * `false` forever and the query would never run once the user arrived.
 */
export interface SelfScopedOptions {
    /** Defaults to always-enabled, for callers already behind an auth guard. */
    enabled?: () => boolean;
}

/** Resolves a SelfScopedOptions into the boolean solid-query expects. */
export function selfScopedEnabled(opts?: SelfScopedOptions): boolean {
    return opts?.enabled?.() ?? true;
}
