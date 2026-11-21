import { describe, it, expect } from "vitest";
import { Linter } from "eslint";
import { join } from "node:path";
import tseslint from "typescript-eslint";
import config from "../eslint.config.js";

/**
 * The design-system contracts in eslint.config.js (the ocidex/* rules), run
 * against small fixtures. The real block is used, so a change to the config is
 * what these tests exercise.
 */
const contracts = config.find((c) => c.plugins?.ocidex !== undefined);
if (contracts === undefined) throw new Error("no ocidex contract block in eslint.config.js");

function lint(code: string, file = "pages/Example.tsx"): string[] {
    const linter = new Linter({ configType: "flat", cwd: process.cwd() });
    const messages = linter.verify(
        code,
        [
            {
                files: ["**/*.tsx"],
                languageOptions: {
                    parser: tseslint.parser,
                    parserOptions: { ecmaFeatures: { jsx: true } },
                },
                plugins: contracts?.plugins,
                rules: contracts?.rules,
            },
        ],
        { filename: join(process.cwd(), "src", file) },
    );
    return messages.map((m) => m.message);
}

describe("design-system contracts", () => {
    it("rejects a hand-written .btn outside Button", () => {
        expect(lint(`const a = <button class="btn btn-sm">x</button>;`)).toHaveLength(1);
        expect(lint(`const a = <button class="btn-primary">x</button>;`)).toHaveLength(1);
        expect(lint(`const a = <Button size="sm">x</Button>;`)).toEqual([]);
    });

    it("sees class strings inside expressions, which the regex tests missed", () => {
        expect(lint(`const a = <button class={p.class ?? "btn btn-sm"}>x</button>;`)).toHaveLength(1);
        expect(lint(`const a = <button classList={{ "btn active": on }}>x</button>;`)).toHaveLength(1);
    });

    it("catches a class after a URL on the same line", () => {
        const code = `const a = <a href="https://example.com/x" class="card">x</a>;`;
        expect(lint(code)).toHaveLength(1);
    });

    it("ignores the class in a comment and in unrelated words", () => {
        expect(lint(`// use class="btn" via <Button>\nconst a = <i class="sidebar-logout-btn" />;`)).toEqual([]);
    });

    it("lets the primitives emit their own classes", () => {
        expect(lint(`const a = <button class="btn btn-sm">x</button>;`, "components/ui/Button.tsx")).toEqual([]);
        expect(lint(`const a = <div class="card">x</div>;`, "components/ui/Card.tsx")).toEqual([]);
    });

    it("rejects the undefined classes anywhere, in any string", () => {
        expect(lint(`const c = "btn-secondary";`)).toHaveLength(1);
        expect(lint("const c = `tab-active ${x}`;")).toHaveLength(1);
        expect(lint(`const c = cond ? "btn-group" : "";`, "components/ui/Button.tsx")).toHaveLength(1);
    });

    it("confines page-header markup and <table> to their primitives", () => {
        expect(lint(`const a = <div class="page-header">x</div>;`)).toHaveLength(1);
        expect(lint(`const a = <table><tbody /></table>;`)).toHaveLength(1);
        expect(lint(`const a = <table><tbody /></table>;`, "components/DataTable.tsx")).toEqual([]);
        expect(lint(`const a = <div class="table-wrapper">x</div>;`)).toEqual([]);
    });
});
