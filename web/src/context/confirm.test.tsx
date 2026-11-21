// @vitest-environment happy-dom
import { describe, it, expect, beforeAll } from "vitest";
import { render, fireEvent } from "@solidjs/testing-library";
import { ConfirmProvider, useConfirm, type ConfirmFn } from "~/context/confirm";
import { stripComments } from "../testing/sourceCode";

// happy-dom's <dialog> has no top layer; the provider only needs the open flag
// and the close event, which these stand in for.
beforeAll(() => {
    HTMLDialogElement.prototype.showModal = function (this: HTMLDialogElement) {
        this.setAttribute("open", "");
    };
    HTMLDialogElement.prototype.close = function (this: HTMLDialogElement) {
        this.removeAttribute("open");
        this.dispatchEvent(new Event("close"));
    };
});

function setup() {
    let confirm: ConfirmFn | undefined;
    function Grab() {
        confirm = useConfirm();
        return null;
    }
    const view = render(() => (
        <ConfirmProvider>
            <Grab />
        </ConfirmProvider>
    ));
    if (confirm === undefined) throw new Error("no confirm");
    return { ...view, confirm };
}

const click = (root: HTMLElement, label: string) => {
    const b = [...root.querySelectorAll("button")].find((x) => x.textContent === label);
    if (b === undefined) throw new Error(`no ${label} button`);
    fireEvent.click(b);
};

describe("ConfirmProvider", () => {
    it("shows the question and resolves true on the verb button", async () => {
        const { confirm, container, getByText } = setup();
        const answer = confirm({ title: 'Delete key "ci"?', body: "Gone for good.", confirmLabel: "Delete key" });
        expect(getByText('Delete key "ci"?')).toBeDefined();
        expect(getByText("Gone for good.")).toBeDefined();
        click(container, "Delete key");
        expect(await answer).toBe(true);
    });

    it("resolves false on Cancel and on any other close (Escape)", async () => {
        const { confirm, container } = setup();
        const cancelled = confirm({ title: "A?", body: "", confirmLabel: "Go" });
        click(container, "Cancel");
        expect(await cancelled).toBe(false);

        const escaped = confirm({ title: "B?", body: "", confirmLabel: "Go" });
        container.querySelector("dialog")?.close();
        expect(await escaped).toBe(false);
    });

    it("styles the commit as danger unless told the action is safe", () => {
        const { confirm, container } = setup();
        void confirm({ title: "A?", body: "", confirmLabel: "Delete" });
        expect(container.querySelector(".confirm-go")?.classList.contains("btn-danger")).toBe(true);
        void confirm({ title: "B?", body: "", confirmLabel: "Re-scan", tone: "default" });
        expect(container.querySelector(".confirm-go")?.classList.contains("btn-primary")).toBe(true);
    });
});

describe("no native dialogs", () => {
    it("nothing under src calls window.confirm, alert or prompt", async () => {
        const { readFileSync, readdirSync, statSync } = await import("node:fs");
        const { join } = await import("node:path");
        const root = join(__dirname, "..");
        const offenders: string[] = [];
        const walk = (dir: string) => {
            for (const e of readdirSync(dir)) {
                const full = join(dir, e);
                if (statSync(full).isDirectory()) walk(full);
                else if (/\.tsx?$/.test(e) && !/\.test\.tsx?$/.test(e)) {
                    const code = stripComments(readFileSync(full, "utf-8"), full);
                    if (/(^|[^.\w])(window\.)?(confirm|alert|prompt)\(\s*[`"']/m.test(code)) offenders.push(full.slice(root.length + 1));
                }
            }
        };
        walk(root);
        expect(offenders).toEqual([]);
    });
});
