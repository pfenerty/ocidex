// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
import { AgentCredentials, agentSecretCommand } from "./AgentCredentials";

const createMutate = vi.fn();
let namespaces: { id: string; capabilities: string[] }[] = [];

vi.mock("~/api/queries", () => ({
    useListNamespaces: () => ({ data: { data: namespaces } }),
    useClusterCredentials: () => ({
        data: [{ id: "k1", name: "prod-agent", prefix: "ocidex_a", createdAt: "2026-01-01T00:00:00Z", ownerId: "u", ownerName: "devowner" }],
        isFetching: false,
        isError: false,
        error: null,
    }),
    useCreateClusterCredential: () => ({ mutate: createMutate, isPending: false }),
    useRotateClusterCredential: () => ({ mutate: vi.fn(), isPending: false }),
    useRevokeClusterCredential: () => ({ mutate: vi.fn(), isPending: false }),
}));
// The shared ConfirmDialog (ocidex-iz0r.7), answered by the test.
const confirmSpy = vi.fn((_options: { title: string; body: unknown }) => Promise.resolve(false));
vi.mock("~/context/confirm", () => ({ useConfirm: () => confirmSpy }));
vi.mock("~/context/toast", () => ({ useToast: () => vi.fn() }));

describe("AgentCredentials", () => {
    beforeEach(() => vi.clearAllMocks());

    it("is absent for a caller who cannot manage the cluster", () => {
        namespaces = [{ id: "ns", capabilities: ["read_private"] }];
        const { container } = render(() => <AgentCredentials clusterId="c" namespaceId="ns" />);
        expect(container.querySelector('[data-testid="agent-credentials"]')).toBeNull();
    });

    it("lists credentials and shows a new key once, inside the secret command", () => {
        namespaces = [{ id: "ns", capabilities: ["manage_cluster", "push_inventory"] }];
        createMutate.mockImplementation((_vars, opts: { onSuccess: (d: { key: string }) => void }) =>
            opts.onSuccess({ key: "ocidex_secret" }),
        );
        const { container, getByText } = render(() => <AgentCredentials clusterId="c" namespaceId="ns" />);
        expect(container.textContent).toContain("prod-agent");
        expect(container.textContent).toContain("devowner");

        fireEvent.click(getByText("New credential"));
        expect(createMutate).toHaveBeenCalledWith({ id: "c" }, expect.anything());
        expect(container.textContent).toContain("OCIDEX_API_KEY='ocidex_secret'");
    });

    it("writes a secret command that is safe to re-run", () => {
        expect(agentSecretCommand("k")).toContain("--dry-run=client -o yaml | kubectl apply -f -");
    });
});
