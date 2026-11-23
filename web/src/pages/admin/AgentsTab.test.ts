// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { mcpCommand } from "./AgentsTab";

describe("mcpCommand", () => {
    // ocidex-mcp reads OCIDEX_URL and OCIDEX_API_KEY (internal/cliconfig).
    it("passes the server and key in the variables ocidex-mcp reads", () => {
        expect(mcpCommand("https://ocidex.example", "ocidex_abc")).toBe(
            "claude mcp add ocidex --env OCIDEX_URL=https://ocidex.example --env OCIDEX_API_KEY=ocidex_abc -- ocidex-mcp",
        );
    });
});
