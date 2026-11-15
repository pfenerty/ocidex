// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
import type { JSX } from "solid-js";
import { AgentTab } from "./AgentTab";

const updateMutate = vi.fn();
const deleteMutate = vi.fn();
const navigate = vi.fn();
let caps: string[] = ["manage_cluster", "push_inventory"];

vi.mock("~/api/queries", () => ({
    useClusterPushes: () => ({
        data: [
            { at: "2026-11-14T10:00:00Z", accepted: false, status: 401, reason: "API key not accepted" },
            { at: "2026-11-14T09:00:00Z", accepted: true, status: 200, workloads: 88, agentVersion: "v1.2.0" },
        ],
        isFetching: false,
        isError: false,
        error: null,
    }),
    useUpdateCluster: () => ({ mutate: updateMutate, isPending: false }),
    useDeleteCluster: () => ({ mutate: deleteMutate, isPending: false }),
    useListNamespaces: () => ({ data: { data: [{ id: "ns", capabilities: caps }] } }),
    useClusterCredentials: () => ({ data: [], isFetching: false, isError: false, error: null }),
    useCreateClusterCredential: () => ({ mutate: vi.fn(), isPending: false }),
    useRotateClusterCredential: () => ({ mutate: vi.fn(), isPending: false }),
    useRevokeClusterCredential: () => ({ mutate: vi.fn(), isPending: false }),
}));
vi.mock("~/context/toast", () => ({ useToast: () => vi.fn() }));
vi.mock("@solidjs/router", () => ({
    useNavigate: () => navigate,
    A: (props: { href: string; children?: JSX.Element }) => <a href={props.href}>{props.children}</a>,
}));

const cluster = {
    id: "c1",
    name: "staging",
    namespaceId: "ns",
    namespaceName: "platform",
    description: "",
    autoIngest: true,
    lastSeenAt: "2026-11-14T09:00:00Z",
    health: { state: "erroring", reason: "API key not accepted" },
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
};

function el(container: HTMLElement, selector: string): Element {
    const found = container.querySelector(selector);
    if (found === null) throw new Error(`no ${selector}`);
    return found;
}

function button(container: HTMLElement, label: string): HTMLButtonElement {
    const b = [...container.querySelectorAll("button")].find((x) => x.textContent.trim() === label);
    if (b === undefined) throw new Error(`no ${label} button`);
    return b;
}

describe("AgentTab", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        caps = ["manage_cluster", "push_inventory"];
        (HTMLDialogElement.prototype as { showModal: () => void }).showModal = vi.fn();
        (HTMLDialogElement.prototype as { close: () => void }).close = vi.fn();
    });

    it("lists recent pushes with the refusal reason", () => {
        const { container } = render(() => <AgentTab cluster={cluster as never} />);
        expect(container.textContent).toContain("API key not accepted");
        expect(container.textContent).toContain("88 containers");
    });

    it("saves name, description and auto-ingest together", () => {
        const { container } = render(() => <AgentTab cluster={cluster as never} />);
        fireEvent.input(el(container, "#agent-settings-name"), {
            target: { value: " staging-2 " },
        });
        fireEvent.change(el(container, "#agent-settings-auto-ingest"), {
            target: { checked: false },
        });
        fireEvent.submit(el(container, "form"));
        expect(updateMutate.mock.calls[0][0]).toEqual({
            id: "c1",
            name: "staging-2",
            description: "",
            autoIngest: false,
        });
    });

    it("retires through the dialog, and leaves the page after a delete", () => {
        deleteMutate.mockImplementation((_id, opts: { onSuccess: () => void }) => opts.onSuccess());
        const { container } = render(() => <AgentTab cluster={cluster as never} />);
        fireEvent.click(button(container, "Retire…"));
        expect(container.textContent).toContain("helm uninstall ocidex-k8s-agent");
        fireEvent.click(button(container, "Pause cluster"));
        expect(updateMutate.mock.calls[0][0]).toMatchObject({ id: "c1", paused: true });
        fireEvent.click(button(container, "Delete staging"));
        expect(deleteMutate).toHaveBeenCalledWith("c1", expect.anything());
        expect(navigate).toHaveBeenCalledWith("/clusters");
    });

    it("offers resume on a paused cluster", () => {
        const { container } = render(() => (
            <AgentTab cluster={{ ...cluster, pausedAt: "2026-11-14T00:00:00Z" } as never} />
        ));
        fireEvent.click(button(container, "Resume"));
        expect(updateMutate.mock.calls[0][0]).toMatchObject({ id: "c1", paused: false });
    });

    it("shows settings and retire only to someone who can manage the cluster", () => {
        caps = ["read_private"];
        const { container } = render(() => <AgentTab cluster={cluster as never} />);
        expect(container.querySelector("form")).toBeNull();
        expect(container.textContent).not.toContain("Retire");
        expect(container.textContent).toContain("Recent pushes");
    });
});
