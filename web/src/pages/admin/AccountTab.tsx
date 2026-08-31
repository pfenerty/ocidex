import { For, Show, createMemo, createSignal, onMount } from "solid-js";
import { useSearchParams } from "@solidjs/router";
import { useToast } from "~/context/toast";
import DataTable from "~/components/DataTable";
import type { Column } from "~/components/DataTable";
import { Button, Card, CardHeader } from "~/components/ui";
import {
    useAuthProviders,
    useMyIdentities,
    useStartIdentityLink,
    useUnlinkIdentity,
} from "~/api/queries";

/** One issuer this account can sign in with. */
interface Identity {
    id: string;
    provider: string;
    display_name: string;
    subject: string;
    email?: string;
    created_at: string;
}

/**
 * What the callback reports back in `?link=`. It arrives as a query parameter
 * rather than a mutation result because the round trip ends in a redirect from
 * the issuer, not in a response to a request this page made.
 */
const LINK_OUTCOMES: Record<string, { message: string; tone: "success" | "error" } | undefined> = {
    ok: { message: "Sign-in method linked", tone: "success" },
    conflict: { message: "That identity is already linked to another account", tone: "error" },
    error: { message: "Could not link that sign-in method", tone: "error" },
};

export function AccountTab() {
    const identities = useMyIdentities();
    const providers = useAuthProviders();
    const startLink = useStartIdentityLink();
    const unlink = useUnlinkIdentity();
    const toast = useToast();
    const [searchParams, setSearchParams] = useSearchParams();
    const [selected, setSelected] = createSignal("");

    onMount(() => {
        const outcome = LINK_OUTCOMES[String(searchParams.link ?? "")];
        if (outcome === undefined) return;
        toast(outcome.message, outcome.tone);
        // Cleared so a reload or a back-navigation does not replay it.
        setSearchParams({ link: undefined }, { replace: true });
    });

    // An issuer already linked is not offered again: a second identity from the
    // same issuer would be the same person, and the server refuses it anyway.
    const linkable = createMemo(() => {
        const held = new Set((identities.data?.identities ?? []).map((i) => i.provider));
        return (providers.data?.providers ?? []).filter((p) => !held.has(p.name));
    });

    // The last identity is the only way back into the account, so the button is
    // not offered rather than offered and refused with a 409.
    const isLastIdentity = () => (identities.data?.identities ?? []).length <= 1;

    // The select is uncontrolled until someone touches it: an empty signal would
    // render a blank box, because "" matches none of the options.
    const chosen = () => {
        const picked = selected();
        return linkable().some((p) => p.name === picked) ? picked : (linkable()[0]?.name ?? "");
    };

    function handleLink(e: Event) {
        e.preventDefault();
        const provider = chosen();
        if (provider === "") return;
        startLink.mutate(provider, {
            // The issuer is a different origin, so this leaves the app. The
            // browser comes back to /admin/account with ?link= set.
            onSuccess: (data) => {
                window.location.href = data.authorize_url;
            },
            onError: () => toast("Could not start linking", "error"),
        });
    }

    const columns: Column<Identity>[] = [
        { header: "Issuer", render: (i) => <>{i.display_name}</> },
        { header: "Subject", render: (i) => <code>{i.subject}</code> },
        {
            header: "Email",
            render: (i) =>
                i.email !== undefined && i.email !== ""
                    ? <>{i.email}</>
                    : <span class="text-muted">—</span>,
        },
        {
            header: "Linked",
            render: (i) => <>{new Date(i.created_at).toLocaleDateString()}</>,
        },
        {
            header: "",
            render: (i) => (
                <Show
                    when={!isLastIdentity()}
                    fallback={<span class="text-muted">Only sign-in method</span>}
                >
                    <Button
                        disabled={unlink.isPending}
                        onClick={() =>
                            unlink.mutate(i.id, {
                                onSuccess: () => toast("Sign-in method removed", "success"),
                                onError: () => toast("Could not remove that sign-in method", "error"),
                            })
                        }
                    >
                        Unlink
                    </Button>
                </Show>
            ),
        },
    ];

    return (
        <>
            <Card class="mb-4">
                <CardHeader title="Link Another Sign-In Method" />
                <Show
                    when={linkable().length > 0}
                    fallback={
                        <p class="text-muted" style={{ "margin-bottom": "0" }}>
                            Every issuer this deployment is configured with is already linked to
                            this account.
                        </p>
                    }
                >
                    <form onSubmit={handleLink}>
                        <div style={{ display: "flex", gap: "0.5rem", "align-items": "center", "flex-wrap": "wrap" }}>
                            <select
                                aria-label="Issuer to link"
                                value={chosen()}
                                onChange={(e) => setSelected(e.currentTarget.value)}
                            >
                                <For each={linkable()}>
                                    {(p) => <option value={p.name}>{p.display_name}</option>}
                                </For>
                            </select>
                            <Button variant="primary" type="submit" disabled={startLink.isPending}>
                                Link
                            </Button>
                        </div>
                        <p class="text-muted" style={{ "margin-top": "0.5rem", "margin-bottom": "0" }}>
                            You will be sent to the issuer to sign in. An identity another account
                            already holds cannot be linked here — the two accounts are never merged.
                        </p>
                    </form>
                </Show>
            </Card>

            <DataTable
                columns={columns}
                rows={identities.data?.identities ?? undefined}
                loading={identities.isFetching}
                isError={identities.isError}
                error={identities.error}
                emptyTitle="No sign-in methods linked"
            />
        </>
    );
}
