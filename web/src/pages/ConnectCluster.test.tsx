// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
import type { JSX } from "solid-js";
import ConnectCluster from "./ConnectCluster";
import { installKeyFor } from "./ClusterDetail/installKey";

const connectMutate = vi.fn();
const navigate = vi.fn();
let namespaces: { id: string; name: string; capabilities?: string[] }[] = [];

vi.mock("~/api/queries", () => ({
    useMyNamespaces: () => ({ data: { data: namespaces }, isSuccess: true }),
    useConnectCluster: () => ({ mutate: connectMutate, isPending: false }),
}));
vi.mock("~/context/toast", () => ({ useToast: () => vi.fn() }));
vi.mock("@solidjs/router", () => ({
    useNavigate: () => navigate,
    A: (props: { href: string; children?: JSX.Element; class?: string }) => (
        <a href={props.href} class={props.class}>
            {props.children}
        </a>
    ),
}));

function must<T>(v: T | null): T {
    if (v === null) throw new Error("missing element");
    return v;
}

describe("ConnectCluster", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        namespaces = [
            { id: "ns-ro", name: "readonly", capabilities: ["read_private"] },
            { id: "ns-1", name: "platform", capabilities: ["manage_cluster", "push_inventory"] },
        ];
    });

    it("offers only namespaces it can connect in, preselecting the first", () => {
        const { container } = render(() => <ConnectCluster />);
        const select = container.querySelector<HTMLSelectElement>("#connect-namespace");
        expect([...(select?.options ?? [])].map((o) => o.value)).toEqual(["ns-1"]);
        expect(select?.value).toBe("ns-1");
    });

    it("connects, keeps the key in memory and goes to the cluster", () => {
        connectMutate.mockImplementation((_body, opts: { onSuccess: (r: unknown) => void }) =>
            opts.onSuccess({ cluster: { id: "c9" }, credential: { key: "ocidex_once", serverUrl: "https://api" } }),
        );
        const { container } = render(() => <ConnectCluster />);
        fireEvent.input(must(container.querySelector("#connect-name")), { target: { value: " prod " } });
        fireEvent.submit(must(container.querySelector("form")));

        expect(connectMutate.mock.calls[0][0]).toEqual({
            namespaceId: "ns-1",
            name: "prod",
            description: undefined,
            autoIngest: true,
        });
        expect(installKeyFor("c9")).toEqual({ key: "ocidex_once", serverUrl: "https://api" });
        expect(navigate).toHaveBeenCalledWith("/clusters/c9");
    });
});
