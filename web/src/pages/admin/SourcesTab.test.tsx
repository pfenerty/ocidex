// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
import { useListRegistries, useListSources, useListNamespaces } from "~/api/queries";
import { SourcesTab } from "~/pages/admin/SourcesTab";
import type { JSX } from "solid-js";

const idleMutation = () => ({ mutate: vi.fn(), isPending: false, data: undefined });
const idleQuery = () => ({ data: undefined, isLoading: false, isError: false, error: null });

vi.mock("~/api/queries", () => ({
    useListRegistries: vi.fn(),
    useListSources: vi.fn(),
    useListNamespaces: vi.fn(),
    useCreateRegistry: () => idleMutation(),
    useUpdateRegistry: () => idleMutation(),
    useDeleteRegistry: () => idleMutation(),
    useTestRegistryConnection: () => idleMutation(),
    useScanRegistry: () => idleMutation(),
    useRegenerateWebhookSecret: () => idleMutation(),
    useGetSystemStatus: () => idleQuery(),
    useListScanJobs: () => idleQuery(),
    useRegistryTrustSummary: () => idleQuery(),
    useRecentDrift: () => idleQuery(),
}));

vi.mock("~/context/toast", () => ({
    useToast: () => vi.fn(),
}));

// The tab reads deep-link params (the cluster Gaps tab sends readers here with
// a host to add or a registry to open), so the mock has to carry them.
let searchParams: Record<string, string | undefined> = {};
const setSearchParams = vi.fn((next: Record<string, string | undefined>) => {
    searchParams = { ...searchParams, ...next };
});

vi.mock("@solidjs/router", () => ({
    useNavigate: () => vi.fn(),
    useSearchParams: () => [searchParams, setSearchParams],
    A: (props: { href: string; children?: JSX.Element }) => (
        <a href={props.href}>{props.children}</a>
    ),
}));

const mockUseListRegistries = vi.mocked(useListRegistries);
const mockUseListSources = vi.mocked(useListSources);
const mockUseListNamespaces = vi.mocked(useListNamespaces);

const baseRegistry = {
    id: "11111111-1111-1111-1111-111111111111",
    name: "unmanaged",
    type: "generic",
    url: "https://a.example.com",
    insecure: false,
    enabled: true,
    has_secret: false,
    has_auth: false,
    visibility: "public",
    scan_mode: "webhook",
};

const managedRegistry = {
    ...baseRegistry,
    id: "22222222-2222-2222-2222-222222222222",
    name: "operator-owned",
    url: "https://b.example.com",
    managed_by: "kubernetes",
    managed_ref: "ocidex-system/prod-registry",
};

/** The `source` row that ADR-039 puts behind a registry. Migration 00053 makes
 *  registry.id a foreign key onto source.id, so the ids are the same value —
 *  which is exactly what the tab joins on. */
function sourceFor(reg: { id: string; name: string }, namespace = "acme") {
    return {
        id: reg.id,
        name: reg.name,
        kind: "oci_registry",
        namespace_id: `ns-${namespace}`,
        namespace_name: namespace,
    };
}

function renderTab(rows: { id: string; name: string }[], sources?: unknown[], namespaces?: unknown[]) {
    mockUseListNamespaces.mockImplementation((() => ({
        data: { data: namespaces ?? [] },
        isLoading: false,
        isError: false,
        error: null,
    })) as unknown as typeof useListNamespaces);
    mockUseListRegistries.mockImplementation((() => ({
        data: { data: rows },
        isLoading: false,
        isError: false,
        error: null,
    })) as unknown as typeof useListRegistries);
    mockUseListSources.mockImplementation((() => ({
        data: { data: sources ?? rows.map((r) => sourceFor(r)) },
        isLoading: false,
        isError: false,
        error: null,
    })) as unknown as typeof useListSources);
    return render(() => <SourcesTab />);
}

function must<T>(value: T | null | undefined, what: string): T {
    if (value === null || value === undefined) throw new Error(`expected ${what}`);
    return value;
}

/** Clicks the Edit button in the row whose name cell matches. */
function clickEditFor(container: HTMLElement, name: string) {
    const row = must(
        Array.from(container.querySelectorAll("tr")).find((tr) => tr.textContent.includes(name)),
        `row for ${name}`,
    );
    const edit = must(
        Array.from(row.querySelectorAll("button")).find((b) => b.textContent.trim() === "Edit"),
        "Edit button",
    );
    fireEvent.click(edit);
}

const formFieldset = (container: HTMLElement) =>
    must(
        container.querySelector<HTMLFieldSetElement>("dialog fieldset"),
        "edit-form fieldset",
    );

const saveButton = (container: HTMLElement) =>
    must(
        Array.from(container.querySelectorAll("dialog button")).find(
            (b) => b.textContent.trim() === "Save",
        ),
        "Save button",
    ) as HTMLButtonElement;

describe("SourcesTab managed-registry guard", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        searchParams = {};
    });

    it("badges a registry owned by an external controller", () => {
        const { container } = renderTab([managedRegistry]);

        const badge = must(
            Array.from(container.querySelectorAll(".badge")).find(
                (b) => b.textContent === "Managed by Kubernetes",
            ),
            "managed badge",
        );
        // The title names the CR, so an admin can find what actually owns the config.
        expect(badge.getAttribute("title")).toContain("ocidex-system/prod-registry");
    });

    it("shows no badge for a registry managed through this UI", () => {
        const { container } = renderTab([baseRegistry]);

        const badges = Array.from(container.querySelectorAll(".badge")).map((b) => b.textContent);
        expect(badges.some((t) => t.startsWith("Managed by"))).toBe(false);
    });

    it("locks the edit form for a managed registry", () => {
        const { container } = renderTab([managedRegistry]);

        clickEditFor(container, "operator-owned");

        const notice = must(
            container.querySelector('[data-testid="managed-notice"]'),
            "managed notice",
        );
        expect(notice.textContent).toContain("ocidex-system/prod-registry");
        // Disabling the fieldset cascades to every control inside it, so a save
        // that the operator would revert seconds later can't be started at all.
        expect(formFieldset(container).disabled).toBe(true);
        expect(saveButton(container).disabled).toBe(true);
    });

    it("leaves the edit form usable for an unmanaged registry", () => {
        const { container } = renderTab([baseRegistry]);

        clickEditFor(container, "unmanaged");

        expect(container.querySelector('[data-testid="managed-notice"]')).toBeNull();
        expect(formFieldset(container).disabled).toBe(false);
        expect(saveButton(container).disabled).toBe(false);
    });
});

// --- ADR-039 source model (ocidex-rj4.5) --------------------------------------
// The tab lists *sources*, not registries: namespace is the ownership axis, and
// an OCI registry is only one of the kinds a source can be.

const headings = (container: HTMLElement) =>
    [...container.querySelectorAll('[data-testid="namespace-heading"]')].map((h) =>
        // Drop the trailing count badge so assertions read as the label.
        h.textContent.replace(/\s*\d+\s*$/, "").trim(),
    );

describe("SourcesTab namespace grouping", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        searchParams = {};
    });

    it("groups sources under the namespace that owns them", () => {
        const { container } = renderTab([baseRegistry, managedRegistry], [
            sourceFor(baseRegistry, "acme"),
            sourceFor(managedRegistry, "widgets"),
        ]);

        expect(headings(container).sort()).toEqual(["acme", "widgets"]);
    });

    it("renders the column header once, not once per namespace", () => {
        // Every namespace used to get its own table, so the nine-column header
        // repeated down the page for groups that were mostly one row each.
        const { container } = renderTab([baseRegistry, managedRegistry], [
            sourceFor(baseRegistry, "acme"),
            sourceFor(managedRegistry, "widgets"),
        ]);

        expect(container.querySelectorAll("thead").length).toBe(1);
        expect(container.querySelectorAll("table").length).toBe(1);
        // Group membership is still on screen — as a spanning row inside the
        // one table rather than as a heading above a table of its own.
        expect(headings(container).sort()).toEqual(["acme", "widgets"]);
        expect(container.querySelectorAll("tr.group-header-row").length).toBe(2);
    });

    it("lists an upload source without any OCI configuration", () => {
        const { container } = renderTab([], [
            {
                id: "33333333-3333-3333-3333-333333333333",
                name: "ci-uploads",
                kind: "upload",
                namespace_id: "ns-acme",
                namespace_name: "acme",
            },
        ]);

        const row = must(
            container.querySelector('[data-testid="upload-source"]'),
            "upload source row",
        );
        expect(row.textContent).toContain("ci-uploads");
        expect(row.textContent).toContain("upload");
        // An upload source has no URL, scan mode or webhook, so it must not be
        // rendered into the registry table where those columns would show as
        // em-dashes implying unset settings that don't exist.
        expect(container.querySelector("table")).toBeNull();
    });

    it("keeps a registry and an upload in the same namespace under one heading", () => {
        const { container } = renderTab([baseRegistry], [
            sourceFor(baseRegistry, "acme"),
            {
                id: "44444444-4444-4444-4444-444444444444",
                name: "ci-uploads",
                kind: "upload",
                namespace_id: "ns-acme",
                namespace_name: "acme",
            },
        ]);

        expect(headings(container)).toEqual(["acme"]);
        expect(container.querySelectorAll('[data-testid="upload-source"]').length).toBe(1);
        expect(container.querySelector("table")).not.toBeNull();
    });

    it("annotates the heading with the namespace's visibility and owner", () => {
        const { container } = renderTab(
            [baseRegistry],
            [sourceFor(baseRegistry, "acme")],
            [
                {
                    id: "ns-acme",
                    name: "acme",
                    visibility: "private",
                    owner_username: "octocat",
                    created_at: "2026-01-01T00:00:00Z",
                    updated_at: "2026-01-01T00:00:00Z",
                },
            ],
        );

        const heading = must(
            container.querySelector('[data-testid="namespace-heading"]'),
            "namespace heading",
        );
        expect(
            must(heading.querySelector('[data-testid="namespace-visibility"]'), "visibility badge")
                .textContent,
        ).toBe("private");
        expect(heading.textContent).toContain("owned by octocat");
    });

    it("falls back to a plain heading when the namespace is not in the list", () => {
        // A source can name a namespace the caller cannot read; the group must
        // still render rather than vanish or claim a visibility it doesn't know.
        const { container } = renderTab([baseRegistry], [sourceFor(baseRegistry, "acme")], []);

        const heading = must(
            container.querySelector('[data-testid="namespace-heading"]'),
            "namespace heading",
        );
        expect(heading.querySelector('[data-testid="namespace-visibility"]')).toBeNull();
        expect(heading.textContent).toContain("acme");
    });
});

// The cluster Gaps tab tells a reader exactly which host has no registry. Both
// of its links pointed at a /registries route that has never existed, so the
// remedy it named ended in a 404. They now land here, carrying what they know.
describe("SourcesTab deep links", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        searchParams = {};
    });

    it("opens the add dialog prefilled from the host that has no registry", () => {
        searchParams = { add: "1", host: "ghcr.io" };
        const { container } = renderTab([]);

        const dialog = must(container.querySelector("dialog"), "dialog");
        expect(dialog.hasAttribute("open")).toBe(true);
        const urls = [...container.querySelectorAll<HTMLInputElement>("dialog input[type=text]")];
        expect(urls.some((i) => i.value === "ghcr.io")).toBe(true);
        // Cleared, or a reload re-opens the dialog over whatever has since been
        // typed into it.
        expect(setSearchParams).toHaveBeenCalledWith(
            { add: undefined, host: undefined },
            { replace: true },
        );
    });

    it("opens the named registry for editing", () => {
        searchParams = { registry: managedRegistry.id };
        const { container } = renderTab([managedRegistry]);

        const dialog = must(container.querySelector("dialog"), "dialog");
        expect(dialog.hasAttribute("open")).toBe(true);
        const values = [...dialog.querySelectorAll<HTMLInputElement>("input[type=text]")].map(
            (i) => i.value,
        );
        expect(values).toContain(managedRegistry.name);
        expect(setSearchParams).toHaveBeenCalledWith({ registry: undefined }, { replace: true });
    });
});
