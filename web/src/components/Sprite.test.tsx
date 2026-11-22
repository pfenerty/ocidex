// @vitest-environment happy-dom
import { describe, it, expect, afterEach } from "vitest";
import { render, cleanup } from "@solidjs/testing-library";
import { Sprite } from "./Sprite";

afterEach(cleanup);

const py = [
    { versionKey: "3.15.2-trixie", critical: 33 },
    { versionKey: "3.14.10-trixie", critical: 35 },
    { versionKey: "3.14.9-trixie", critical: 75 },
    { versionKey: "3.14.4", critical: 0 },
    { versionKey: "3.14.8-trixie", critical: 75 },
];

describe("Sprite", () => {
    it("draws one bar per version of the newest variant, oldest first", () => {
        const { container } = render(() => <Sprite points={py} />);
        expect(container.querySelectorAll(".sprite-bar")).toHaveLength(4);
        expect(container.querySelector("svg")?.getAttribute("aria-label")).toBe(
            "Critical findings, oldest to newest: 3.14.8-trixie 75, 3.14.9-trixie 75, 3.14.10-trixie 35, 3.15.2-trixie 33",
        );
    });

    it("hatches what a version fixed and marks what it added", () => {
        const rising = [
            { versionKey: "3", critical: 9 },
            { versionKey: "2", critical: 4 },
            { versionKey: "1", critical: 6 },
        ];
        const { container } = render(() => <Sprite points={rising} />);
        expect(container.querySelectorAll(".sprite-fixed")).toHaveLength(1);
        expect(container.querySelectorAll(".sprite-added")).toHaveLength(1);
    });

    it("keeps at most six bars", () => {
        const many = Array.from({ length: 10 }, (_, i) => ({ versionKey: `1.${10 - i}`, critical: i }));
        const { container } = render(() => <Sprite points={many} />);
        expect(container.querySelectorAll(".sprite-bar")).toHaveLength(6);
    });

    it("says so when there is no history", () => {
        const { container } = render(() => <Sprite points={[{ versionKey: "1" }]} />);
        expect(container.querySelector(".sprite-empty")).not.toBeNull();
        expect(container.querySelector("svg")?.getAttribute("aria-label")).toBe("No version history");
    });
});
