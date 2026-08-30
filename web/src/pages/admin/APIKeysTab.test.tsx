// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
import { useListAPIKeys, useCreateAPIKey, useDeleteAPIKey } from "~/api/queries";
import { APIKeysTab } from "~/pages/admin/APIKeysTab";

const createMutate = vi.fn();

vi.mock("~/api/queries", () => ({
    useListAPIKeys: vi.fn(),
    useCreateAPIKey: vi.fn(),
    useDeleteAPIKey: vi.fn(),
}));

vi.mock("~/context/toast", () => ({ useToast: () => vi.fn() }));

const mockList = vi.mocked(useListAPIKeys);
const mockCreate = vi.mocked(useCreateAPIKey);
const mockDelete = vi.mocked(useDeleteAPIKey);

const ALL = [
    "read_private",
    "ingest",
    "trigger_scan",
    "push_inventory",
    "delete_artifact",
    "manage_source",
    "manage_cluster",
    "read_secret",
    "manage_member",
    "delete_namespace",
];

function key(name: string, capabilities: string[] | null) {
    return {
        id: `k-${name}`,
        name,
        prefix: "ocidex_ab",
        capabilities,
        created_at: "2026-01-01T00:00:00Z",
    };
}

function stubKeys(keys: ReturnType<typeof key>[]) {
    mockList.mockReturnValue({
        data: { keys },
        isFetching: false,
        isError: false,
        error: null,
    } as unknown as ReturnType<typeof useListAPIKeys>);
}

function must<T>(value: T | null | undefined, what: string): T {
    if (value === null || value === undefined) throw new Error(`expected ${what}`);
    return value;
}

describe("APIKeysTab", () => {
    beforeEach(() => {
        stubKeys([]);
        mockCreate.mockReturnValue({
            mutate: createMutate,
            isPending: false,
        } as unknown as ReturnType<typeof useCreateAPIKey>);
        mockDelete.mockReturnValue({
            mutate: vi.fn(),
            isPending: false,
        } as unknown as ReturnType<typeof useDeleteAPIKey>);
    });

    afterEach(() => vi.clearAllMocks());

    function fillName(container: HTMLElement, name: string) {
        const input = must(container.querySelector<HTMLInputElement>('input[type="text"]'), "name input");
        fireEvent.input(input, { target: { value: name } });
    }

    function selectPreset(container: HTMLElement, value: string) {
        const select = must(container.querySelector<HTMLSelectElement>('select[aria-label="Key capabilities"]'), "preset select");
        fireEvent.change(select, { target: { value } });
    }

    it("asks for no capabilities by default, which the API reads as all of them", () => {
        const { container } = render(() => <APIKeysTab />);
        fillName(container, "ci");
        fireEvent.submit(must(container.querySelector("form"), "form"));

        expect(createMutate).toHaveBeenCalledWith(
            { name: "ci", capabilities: [] },
            expect.anything(),
        );
    });

    it("sends only read_private for a read-only key", () => {
        const { container } = render(() => <APIKeysTab />);
        fillName(container, "reader");
        selectPreset(container, "read");
        fireEvent.submit(must(container.querySelector("form"), "form"));

        expect(createMutate).toHaveBeenCalledWith(
            { name: "reader", capabilities: ["read_private"] },
            expect.anything(),
        );
    });

    it("hides the capability picker until it is asked for", () => {
        const { container } = render(() => <APIKeysTab />);
        expect(container.querySelector('[data-testid="capability-picker"]')).toBeNull();

        selectPreset(container, "custom");
        const picker = must(container.querySelector('[data-testid="capability-picker"]'), "picker");
        expect(picker.querySelectorAll('input[type="checkbox"]').length).toBe(ALL.length);
    });

    it("sends exactly the capabilities that were ticked", () => {
        const { container } = render(() => <APIKeysTab />);
        fillName(container, "scanner");
        selectPreset(container, "custom");

        const boxes = Array.from(
            must(container.querySelector('[data-testid="capability-picker"]'), "picker")
                .querySelectorAll<HTMLInputElement>('input[type="checkbox"]'),
        );
        fireEvent.click(boxes[ALL.indexOf("trigger_scan")]);
        fireEvent.click(boxes[ALL.indexOf("read_private")]);
        fireEvent.submit(must(container.querySelector("form"), "form"));

        expect(createMutate).toHaveBeenCalledWith(
            { name: "scanner", capabilities: ["trigger_scan", "read_private"] },
            expect.anything(),
        );
    });

    it("unticking a capability removes it again", () => {
        const { container } = render(() => <APIKeysTab />);
        fillName(container, "scanner");
        selectPreset(container, "custom");

        const boxes = Array.from(
            must(container.querySelector('[data-testid="capability-picker"]'), "picker")
                .querySelectorAll<HTMLInputElement>('input[type="checkbox"]'),
        );
        const ingest = boxes[ALL.indexOf("ingest")];
        fireEvent.click(ingest);
        fireEvent.click(ingest);
        fireEvent.submit(must(container.querySelector("form"), "form"));

        expect(createMutate).toHaveBeenCalledWith(
            { name: "scanner", capabilities: [] },
            expect.anything(),
        );
    });

    it("collapses a key holding everything to a single badge", () => {
        stubKeys([key("wide", ALL)]);
        const { container } = render(() => <APIKeysTab />);

        const badges = Array.from(container.querySelectorAll(".badge")).map((b) => b.textContent);
        expect(badges).toEqual(["all"]);
    });

    it("names the capabilities of a narrow key", () => {
        stubKeys([key("narrow", ["ingest", "read_private"])]);
        const { container } = render(() => <APIKeysTab />);

        const badges = Array.from(container.querySelectorAll(".badge")).map((b) => b.textContent);
        expect(badges).toEqual(["ingest", "read private"]);
    });

    it("says so when a key can do nothing", () => {
        stubKeys([key("inert", [])]);
        const { container } = render(() => <APIKeysTab />);

        expect(container.textContent).toContain("none");
    });
});
