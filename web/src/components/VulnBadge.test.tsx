// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { render } from "@solidjs/testing-library";
import { VulnCountBadges } from "./VulnBadge";

// ocidex-nps9.19: zero segments rendered in full severity colour, so
// "0 0 0 0 1" read as an alarm.
describe("VulnCountBadges", () => {
    it("mutes zero segments and colours only real counts", () => {
        const { container } = render(() => <VulnCountBadges criticalCount={0} highCount={2} unknownCount={1} />);
        const segs = [...container.querySelectorAll(".vuln-chip-n")];
        expect(segs.map((s) => s.textContent)).toEqual(["0", "2", "0", "0", "1"]);
        expect(segs[0].className).toContain("vuln-chip-zero");
        expect(segs[0].className).not.toContain("sev-critical");
        expect(segs[1].className).toContain("sev-high");
    });
});
