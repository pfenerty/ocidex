// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
import { useListRegistries } from "~/api/queries";
import { RegistriesTab } from "~/pages/admin/RegistriesTab";
import type { JSX } from "solid-js";

const idleMutation = () => ({ mutate: vi.fn(), isPending: false, data: undefined });
const idleQuery = () => ({ data: undefined, isLoading: false, isError: false, error: null });

vi.mock("~/api/queries", () => ({
    useListRegistries: vi.fn(),
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

vi.mock("@solidjs/router", () => ({
    useNavigate: () => vi.fn(),
    A: (props: { href: string; children?: JSX.Element }) => (
        <a href={props.href}>{props.children}</a>
    ),
}));

const mockUseListRegistries = vi.mocked(useListRegistries);

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

function renderTab(rows: unknown[]) {
    mockUseListRegistries.mockImplementation((() => ({
        data: { data: rows },
        isLoading: false,
        isError: false,
        error: null,
    })) as unknown as typeof useListRegistries);
    return render(() => <RegistriesTab />);
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

describe("RegistriesTab managed-registry guard", () => {
    beforeEach(() => {
        vi.clearAllMocks();
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
