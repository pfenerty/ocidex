// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
import { useToggleWatch } from "~/api/queries";
import { useAuth } from "~/context/auth";
import WatchStar from "~/components/WatchStar";

vi.mock("~/api/queries", () => ({ useToggleWatch: vi.fn() }));
vi.mock("~/context/auth", () => ({ useAuth: vi.fn() }));

const mockToggle = vi.mocked(useToggleWatch);
const mockAuth = vi.mocked(useAuth);

const mutate = vi.fn();

/** signedIn stubs the auth context; passing false makes the visitor anonymous. */
function signedIn(yes: boolean) {
    mockAuth.mockReturnValue({
        user: (() => (yes ? { id: "u1", display_name: "me", role: "member" } : undefined)),
        refetch: vi.fn(),
    } as unknown as ReturnType<typeof useAuth>);
}

function star(props: { watched: boolean }) {
    return render(() => <WatchStar artifactId="a1" watched={props.watched} />);
}

beforeEach(() => {
    vi.clearAllMocks();
    signedIn(true);
    mockToggle.mockReturnValue({
        mutate,
        isPending: false,
    } as unknown as ReturnType<typeof useToggleWatch>);
});

describe("WatchStar", () => {
    it("renders nothing for a signed-out visitor", () => {
        signedIn(false);
        const { container } = star({ watched: false });

        // Not merely disabled: an anonymous visitor has no watchlist, so an
        // inert star would read as "not watched" rather than "not applicable".
        expect(container.querySelector("button")).toBe(null);
    });

    it("reports its state through aria-pressed, not only through the icon fill", () => {
        const { container: off } = star({ watched: false });
        expect(off.querySelector("button")?.getAttribute("aria-pressed")).toBe("false");

        const { container: on } = star({ watched: true });
        expect(on.querySelector("button")?.getAttribute("aria-pressed")).toBe("true");
    });

    it("labels the action, not the state", () => {
        // "Watch" on an unwatched artifact says what clicking does; a label
        // that read "Not watched" would leave the outcome to be guessed.
        expect(star({ watched: false }).container.textContent).toContain("Watch");
        expect(star({ watched: true }).container.textContent).toContain("Unwatch");
    });

    it("sends the intended next state, not the current one", () => {
        const { container } = star({ watched: false });
        fireEvent.click(container.querySelector("button")!);
        expect(mutate).toHaveBeenCalledWith({ artifactId: "a1", watched: true });

        mutate.mockClear();

        const { container: on } = star({ watched: true });
        fireEvent.click(on.querySelector("button")!);
        expect(mutate).toHaveBeenCalledWith({ artifactId: "a1", watched: false });
    });

    it("disables itself while a toggle is in flight", () => {
        mockToggle.mockReturnValue({
            mutate,
            isPending: true,
        } as unknown as ReturnType<typeof useToggleWatch>);

        const { container } = star({ watched: false });
        expect((container.querySelector("button")!).disabled).toBe(true);
    });

    // The star reads `watched` from props on every render rather than seeding
    // local state from it. That is what lets useToggleWatch's optimistic cache
    // write drive the visual flip — and what stops the star from sticking on a
    // stale value when the mutation is rolled back.
    it("follows the prop when the cached state changes underneath it", () => {
        let watched = false;
        const { container } = render(() => <WatchStar artifactId="a1" watched={watched} />);
        expect(container.querySelector("button")?.getAttribute("aria-pressed")).toBe("false");

        watched = true;
        const { container: next } = render(() => <WatchStar artifactId="a1" watched={watched} />);
        expect(next.querySelector("button")?.getAttribute("aria-pressed")).toBe("true");
    });
});
