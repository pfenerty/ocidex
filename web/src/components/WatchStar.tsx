import { Show } from "solid-js";
import { Star } from "lucide-solid";
import { useAuth } from "~/context/auth";
import { useToggleWatch } from "~/api/queries";

interface WatchStarProps {
    artifactId: string;
    /** Current watch state, read from the artifact detail response. */
    watched: boolean;
    class?: string;
}

/**
 * WatchStar toggles an artifact on the caller's watchlist (ocidex-998g.3).
 *
 * It renders nothing for a signed-out visitor. A star that is always dark and
 * silently does nothing on click is worse than no star: there is no watchlist
 * to put anything on, and the control would read as "not watched" rather than
 * "not applicable".
 *
 * The optimistic update lives in useToggleWatch, not here — this component
 * reads `watched` straight from the artifact detail cache, so the star follows
 * whatever the mutation writes there and needs no local state of its own to
 * fall out of sync.
 */
export default function WatchStar(props: WatchStarProps) {
    const { user } = useAuth();
    const toggle = useToggleWatch();

    const label = () => (props.watched ? "Unwatch" : "Watch");

    return (
        <Show when={user()}>
            <button
                type="button"
                class={props.class ?? "btn btn-sm"}
                aria-pressed={props.watched}
                aria-label={`${label()} this artifact`}
                title={
                    props.watched
                        ? "Remove this artifact from your watchlist"
                        : "Add this artifact to your watchlist"
                }
                disabled={toggle.isPending}
                onClick={() =>
                    toggle.mutate({ artifactId: props.artifactId, watched: !props.watched })
                }
            >
                <Star size={14} fill={props.watched ? "currentColor" : "none"} />
                {label()}
            </button>
        </Show>
    );
}
