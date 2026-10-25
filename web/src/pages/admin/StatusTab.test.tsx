// @vitest-environment happy-dom
import { describe, it, expect, vi } from "vitest";
import { render } from "@solidjs/testing-library";
import { useGetSystemStatus, useListRegistries } from "~/api/queries";
import { StatusTab } from "./StatusTab";

vi.mock("~/api/queries", () => ({ useGetSystemStatus: vi.fn(), useListRegistries: vi.fn() }));

// ocidex-nps9.25: every card wore a red edge, and "last polled" contradicted
// the Sources page's "last walk".
describe("StatusTab", () => {
    vi.mocked(useGetSystemStatus).mockReturnValue({
        isLoading: false,
        isError: false,
        error: null,
        data: {
            enrichment: { enabled: true, workers: 2, queueSize: 0 },
            scanner: { enabled: false, pollerEnabled: true },
            nats: { enabled: true, url: "nats://x" },
            scanJobs: { queued: 0, running: 0, succeeded24h: 3, failed24h: 1 },
            db: { ok: true, latencyMs: 2 },
        },
    } as never);
    vi.mocked(useListRegistries).mockReturnValue({
        isFetching: false,
        isError: false,
        error: null,
        data: { data: [{ id: "r1", name: "ghcr.io/othercorp", scanMode: "poll", lastPolledAt: "2026-10-24T10:00:00Z" }] },
    } as never);

    it("colours each card's edge by its state", () => {
        const { container } = render(() => <StatusTab />);
        const edge = (label: string) =>
            [...container.querySelectorAll(".stat-card")].find((c) => c.querySelector(".stat-label")?.textContent === label)?.className;
        expect(edge("Enrichment")).toContain("stat-card-ok");
        expect(edge("Scanner")).toContain("stat-card-off");
        expect(edge("Failed (24 h)")).toContain("stat-card-bad");
        expect(edge("Database")).toContain("stat-card-ok");
    });

    it("tells a requested walk from a finished one", () => {
        const { container } = render(() => <StatusTab />);
        const headers = [...container.querySelectorAll("thead th")].map((th) => th.textContent.trim());
        expect(headers).toContain("Walk requested");
        expect(headers).toContain("Last walk");
        expect(container.querySelector("tbody tr")?.textContent).toContain("Never");
    });
});
