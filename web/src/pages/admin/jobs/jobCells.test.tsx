// @vitest-environment happy-dom
import { describe, it, expect, vi } from "vitest";
import { render } from "@solidjs/testing-library";
import { retryColumn, workerColumn, type JobRow } from "./jobCells";

const row = (state: string): JobRow =>
    ({ id: "j1", state, workerId: "glados", attempts: 1, createdAt: "2026-10-20T00:00:00Z" });

const cell = (el: () => unknown) => render(() => <>{el()}</>).container;

// ocidex-nps9.26: queued jobs showed a worker and offered no action.
describe("job cells", () => {
    it("names a worker only for a running job", () => {
        const col = workerColumn<JobRow>();
        expect(cell(() => col.render(row("running"))).textContent).toBe("glados");
        expect(cell(() => col.render(row("queued"))).textContent).toBe("—");
    });

    it("offers Cancel on queued rows and Retry on failed ones", () => {
        const retry = { isPending: false, mutate: vi.fn() };
        const cancel = { isPending: false, mutate: vi.fn() };
        const col = retryColumn<JobRow>(retry, cancel);
        expect(cell(() => col.render(row("queued"))).textContent).toBe("Cancel");
        expect(cell(() => col.render(row("failed"))).textContent).toBe("Retry");
        expect(cell(() => col.render(row("running"))).textContent).toBe("");
    });

    it("offers no Cancel where the queue has none", () => {
        const col = retryColumn<JobRow>({ isPending: false, mutate: vi.fn() });
        expect(cell(() => col.render(row("queued"))).textContent).toBe("");
    });
});
