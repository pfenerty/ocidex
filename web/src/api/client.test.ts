import { describe, it, expect } from "vitest";
import { unwrap, isUnauthorized, APIClientError } from "./client";

function result(status: number, body: unknown) {
    return Promise.resolve({
        error: body,
        response: new Response(null, { status }),
    });
}

describe("unwrap", () => {
    it("returns data on success", async () => {
        const data = await unwrap(
            Promise.resolve({ data: { id: "a" }, response: new Response(null, { status: 200 }) }),
        );
        expect(data).toEqual({ id: "a" });
    });

    // The redirect this guards against is the whole reason a public CVE page
    // bounced signed-out visitors to /login: one authenticated sibling request
    // navigated the browser out from under an otherwise-200 page.
    //
    // This file is a .test.ts, so it runs in vitest's `node` environment where
    // there is no `window` (see vite.config.ts environmentMatchGlobs). A reach
    // for window.location therefore fails as a ReferenceError rather than an
    // APIClientError — which makes asserting the error type a real guard, not a
    // restatement of the happy path.
    it("throws on 401 rather than touching window.location", async () => {
        expect(typeof globalThis.window).toBe("undefined");

        await expect(unwrap(result(401, { detail: "unauthorized" }))).rejects.toBeInstanceOf(
            APIClientError,
        );
    });

    it("preserves the status on the thrown error", async () => {
        await expect(unwrap(result(404, { detail: "nope" }))).rejects.toMatchObject({ status: 404 });
    });
});

describe("isUnauthorized", () => {
    it("is true only for a 401 APIClientError", () => {
        expect(isUnauthorized(new APIClientError(401, {}))).toBe(true);
        expect(isUnauthorized(new APIClientError(403, {}))).toBe(false);
        expect(isUnauthorized(new Error("boom"))).toBe(false);
        expect(isUnauthorized(undefined)).toBe(false);
    });
});
