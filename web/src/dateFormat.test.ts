// @vitest-environment node
import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

/**
 * Dates read one way app-wide: formatDate / formatDateTime ("Oct 24, 2026,
 * 4:47 PM") or TimestampCell (relative, with that as its tooltip). A bare
 * toLocaleDateString() renders "9/6/2026", which a US reader and an EU reader
 * read as different days (ocidex-nps9.27). This keeps it from coming back.
 */
const SRC = join(__dirname);
const ALLOWED = new Set(["utils/format.ts"]);

function files(dir: string): string[] {
    return readdirSync(dir).flatMap((name) => {
        const p = join(dir, name);
        if (statSync(p).isDirectory()) return name === "types" ? [] : files(p);
        return /\.(ts|tsx)$/.test(name) && !/\.test\.tsx?$/.test(name) ? [p] : [];
    });
}

describe("date formatting", () => {
    it("goes through utils/format everywhere", () => {
        const offenders = files(SRC)
            .filter((p) => !ALLOWED.has(relative(SRC, p)))
            .filter((p) => /toLocaleDateString\(|toLocaleTimeString\(|new Date\([^)]*\)\.toLocaleString\(/.test(readFileSync(p, "utf8")))
            .map((p) => relative(SRC, p));
        expect(offenders).toEqual([]);
    });
});
