// @vitest-environment happy-dom
import { describe, it, expect, afterEach } from "vitest";
import { render, cleanup } from "@solidjs/testing-library";
import { StatBlock } from "./StatBlock";

afterEach(cleanup);

describe("StatBlock", () => {
    it("scales each bar against its catalog maximum", () => {
        const { container } = render(() => (
            <StatBlock
                rows={[
                    { label: "PKG", title: "Packages", value: 22120, max: 33918 },
                    { label: "CRT", title: "Critical", value: 33, max: 47, tone: "critical" },
                ]}
            />
        ));
        const bars = [...container.querySelectorAll<HTMLElement>(".stat-block-bar span")];
        expect(bars.map((b) => b.style.width)).toEqual(["65.2%", "70.2%"]);
        expect(bars[1].className).toBe("stat-block-critical");
        expect(container.querySelector(".stat-block-value")?.textContent).toBe("22,120");
    });

    it("leaves out a figure with no value instead of drawing a zero", () => {
        const { container } = render(() => (
            <StatBlock rows={[{ label: "CRT", title: "Critical", value: undefined, max: 47 }]} />
        ));
        expect(container.querySelector(".stat-block")).toBeNull();
    });
});
