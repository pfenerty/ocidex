import "./NotFound.css";
import { A, useLocation } from "@solidjs/router";
import { For, Show } from "solid-js";
import { Button } from "~/components/ui";
import { openCommandPalette, isAppleShortcut } from "~/components/CommandPalette";
import { useArtifactSearch, MIN_SEARCH_TERM } from "~/api/queries/search";

/** Bar heights for the empty chart above the title: tall grass, nothing in it. */
const GRASS = [9, 16, 12, 22, 14, 19, 10, 24, 15, 11, 20, 13, 17, 8];

/** The last path segment, as a search term for "did you mean". */
function guessTerm(pathname: string): string {
    const last = pathname.split("/").filter((s) => s !== "").pop() ?? "";
    let term = last;
    try {
        term = decodeURIComponent(last);
    } catch {
        // A malformed escape is still worth searching for as typed.
    }
    // A UUID or a number is an id, not a name anyone would mistype.
    return /^[0-9a-f-]{8,}$/i.test(term) || /^\d+$/.test(term) ? "" : term;
}

export default function NotFound() {
    const location = useLocation();
    const term = () => guessTerm(location.pathname);
    const search = useArtifactSearch(() => (term().length >= MIN_SEARCH_TERM ? term() : ""));
    const suggestion = () => search.data?.[0];

    return (
        <div class="empty-state not-found min-h-[60vh]">
            <div class="not-found-grass" aria-hidden="true">
                <For each={GRASS}>{(h) => <i class={`grass-${h}`} />}</For>
            </div>
            <h2 class="not-found-title">A wild 404 appeared.</h2>
            <p>
                Nothing is indexed at <code>{location.pathname}</code>.
                <Show when={suggestion()}>
                    {(s) => (
                        <>
                            {" "}
                            Did you mean <A href={s().path}>{s().label}</A>?
                        </>
                    )}
                </Show>
            </p>
            <div class="not-found-actions">
                <Button variant="primary" onClick={openCommandPalette}>
                    Search {isAppleShortcut() ? "⌘K" : "Ctrl K"}
                </Button>
                <Button as={A} href="/artifacts">
                    All artifacts
                </Button>
                {/* `end`: without it the router marks "/" active on every path. */}
                <Button as={A} href="/" end>
                    Back to home
                </Button>
            </div>
        </div>
    );
}
