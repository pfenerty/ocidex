// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
import type { JSX } from "solid-js";
import { InstallAgent } from "./InstallAgent";
import { forgetInstallKey, helmInstallCommand, rememberInstallKey } from "./installKey";

const createMutate = vi.fn();
let caps: string[] = [];

vi.mock("~/api/queries", () => ({
    useListNamespaces: () => ({ data: { data: [{ id: "ns", capabilities: caps }] } }),
    useCreateClusterCredential: () => ({ mutate: createMutate, isPending: false }),
}));
vi.mock("~/context/toast", () => ({ useToast: () => vi.fn() }));
vi.mock("@solidjs/router", () => ({
    A: (props: { href: string; children?: JSX.Element; class?: string }) => (
        <a href={props.href} class={props.class}>
            {props.children}
        </a>
    ),
}));

function renderCard(health: { state: string; reason?: string } = { state: "never_reported" }) {
    return render(() => <InstallAgent clusterId="c1" clusterName="prod" namespaceId="ns" health={health} />);
}

describe("InstallAgent", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        forgetInstallKey("c1");
        caps = ["manage_cluster", "push_inventory"];
    });

    it("prefers the server's public URL over the page origin", () => {
        rememberInstallKey("c1", { key: "ocidex_k", serverUrl: "https://api.example.com" });
        const { container } = renderCard();
        expect(container.querySelector("pre")?.textContent).toBe(
            helmInstallCommand({ serverUrl: "https://api.example.com", clusterId: "c1", key: "ocidex_k" }),
        );
    });

    it("keeps the key out of the values.yaml form", () => {
        rememberInstallKey("c1", { key: "ocidex_k" });
        const { container, getByText } = renderCard();
        fireEvent.click(getByText("values.yaml"));
        const pre = container.querySelector("pre")?.textContent ?? "";
        expect(pre).toContain("secretName: ocidex-k8s-agent-secrets");
        expect(pre).not.toContain("ocidex_k");
    });

    it("mints a fresh credential when the one-time key is gone", () => {
        createMutate.mockImplementation((_v, opts: { onSuccess: (d: { key: string }) => void }) =>
            opts.onSuccess({ key: "ocidex_new" }),
        );
        const { container, getByText } = renderCard();
        expect(container.querySelector("pre")).toBeNull();
        fireEvent.click(getByText("Get install command"));
        expect(container.querySelector("pre")?.textContent).toContain("apiKey.value=ocidex_new");
    });

    it("sends someone who cannot mint to an API key instead", () => {
        caps = ["read_private"];
        const { container } = renderCard();
        expect(container.textContent).not.toContain("Get install command");
        expect(container.querySelector('a[href*="/admin/keys"]')).not.toBeNull();
    });

    it("shows the refusal reason while erroring", () => {
        const { container } = renderCard({ state: "erroring", reason: "The agent's API key was not accepted" });
        expect(container.querySelector('[data-testid="install-erroring"]')?.textContent).toContain(
            "API key was not accepted",
        );
        expect(container.textContent).not.toContain("Waiting for the first snapshot");
    });
});
