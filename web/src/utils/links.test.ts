import { describe, it, expect } from "vitest";
import { safeHref } from "./links";

describe("safeHref", () => {
    it.each([
        "https://github.com/owner/repo",
        "http://example.com/x?y=1#z",
        "HTTPS://EXAMPLE.COM",
        "mailto:security@example.com",
    ])("keeps %s", (url) => {
        expect(safeHref(url)).toBe(url);
    });

    it.each([
        "javascript:alert(1)",
        "JavaScript:alert(1)",
        " javascript:alert(1)",
        "java\tscript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox(1)",
        "file:///etc/passwd",
        "//evil.example/x",
        "/relative/path",
        "github.com/owner/repo",
        "",
    ])("refuses %j", (url) => {
        expect(safeHref(url)).toBeUndefined();
    });

    it("refuses null and undefined", () => {
        expect(safeHref(null)).toBeUndefined();
        expect(safeHref(undefined)).toBeUndefined();
    });
});
