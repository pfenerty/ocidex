import { For, Show } from "solid-js";
import { API_BASE_URL } from "~/api/client";
import { GitHubMark } from "~/components/icons/GitHubMark";
import { useAuthProviders } from "~/api/queries";

/**
 * The sign-in buttons are drawn from the API rather than hardcoded, because the
 * set of issuers is a deployment decision: an installation may run GitHub, a
 * corporate OIDC issuer, both, or neither.
 *
 * The single-provider case has to look exactly like the hardcoded GitHub button
 * did — one full-width button, no chooser — since that is what almost every
 * installation still is.
 */
export default function Login() {
    const providers = useAuthProviders();

    return (
        <div class="flex flex-1 items-center justify-center bg-[var(--color-bg)]">
            <div class="flex flex-col items-center gap-8 p-12 bg-[var(--color-surface)] border border-[var(--color-border)] rounded-xl w-full max-w-[360px]">
                {/* Logo */}
                <div class="text-center">
                    <h1 class="text-3xl font-bold tracking-tight text-[var(--color-text)] leading-none mb-1.5">
                        OCI<span class="text-[var(--color-primary)]">Dex</span>
                    </h1>
                    <p class="text-[0.8125rem] text-[var(--color-text-muted)] tracking-widest uppercase">
                        SBOM Explorer
                    </p>
                </div>

                {/* Divider */}
                <div class="w-full h-px bg-[var(--color-border)]" />

                {/* Sign-in */}
                <div class="text-center w-full">
                    <p class="text-[0.8125rem] text-[var(--color-text-muted)] mb-5">
                        Sign in to access the dashboard
                    </p>
                    <Show
                        when={providers.data?.providers?.length}
                        fallback={
                            <p class="text-[0.8125rem] text-[var(--color-text-muted)]">
                                {providers.isError
                                    ? "Sign-in is unavailable — could not reach the API."
                                    : providers.isPending
                                      ? "Loading sign-in options…"
                                      : "No sign-in method is configured on this deployment."}
                            </p>
                        }
                    >
                        <div class="flex flex-col gap-2.5">
                            <For each={providers.data?.providers}>
                                {(p) => (
                                    <a
                                        href={`${API_BASE_URL}${p.login_path}`}
                                        target="_self"
                                        class="inline-flex items-center gap-2.5 px-5 py-2.5 bg-[var(--color-elevated)] border border-[var(--color-border)] rounded-md text-[var(--color-text)] text-sm font-medium no-underline transition-[background,border-color] duration-150 w-full justify-center hover:bg-[var(--color-surface-hover)] hover:border-[var(--color-border-hover)]"
                                    >
                                        {/* Only GitHub has a mark of its own. An
                                            operator's OIDC issuer is named, not
                                            branded. */}
                                        <Show when={p.name === "github"}>
                                            <GitHubMark />
                                        </Show>
                                        Continue with {p.display_name}
                                    </a>
                                )}
                            </For>
                        </div>
                    </Show>
                </div>
            </div>
        </div>
    );
}
