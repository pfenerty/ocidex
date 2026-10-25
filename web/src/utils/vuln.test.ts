import { describe, it, expect } from "vitest";
import { parseCvssVector, cvssVersion, noFixLabel } from "./vuln";

describe("cvssVersion", () => {
    it("extracts v3 prefix", () => {
        expect(cvssVersion("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBe("CVSSv3.1");
    });

    it("extracts v4 prefix", () => {
        expect(cvssVersion("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")).toBe("CVSSv4.0");
    });
});

describe("parseCvssVector", () => {
    it("returns null for an empty vector", () => {
        expect(parseCvssVector("")).toBeNull();
    });

    it("decodes a v3.1 vector unchanged", () => {
        const result = parseCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        expect(result).toEqual({
            version: "CVSSv3.1",
            metrics: [
                { label: "Network", variant: "danger" },
                { label: "Low Complexity", variant: "warning" },
                { label: "No Privileges", variant: "danger" },
                { label: "No Interaction", variant: "warning" },
                { label: "High confidentiality impact", variant: "danger" },
                { label: "High integrity impact", variant: "danger" },
                { label: "High availability impact", variant: "danger" },
            ],
        });
    });

    it("decodes a v4.0 vector with full impact metrics", () => {
        const result = parseCvssVector(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        );
        expect(result).toEqual({
            version: "CVSSv4.0",
            metrics: [
                { label: "Network", variant: "danger" },
                { label: "Low Complexity", variant: "warning" },
                { label: "No Privileges", variant: "danger" },
                { label: "No Interaction", variant: "warning" },
                { label: "High confidentiality impact", variant: "danger" },
                { label: "High integrity impact", variant: "danger" },
                { label: "High availability impact", variant: "danger" },
            ],
        });
        // AT:N and SC/SI/SA:N are all "omit" values — no chips for them.
        expect(result?.metrics.some((m) => m.label.includes("Attack Requirements"))).toBe(false);
        expect(result?.metrics.some((m) => m.label.includes("downstream"))).toBe(false);
    });

    it("decodes v4-specific AT and UI values", () => {
        const result = parseCvssVector(
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        );
        expect(result?.metrics).toContainEqual({ label: "Attack Requirements", variant: "warning" });
        expect(result?.metrics).toContainEqual({ label: "Passive Interaction", variant: "" });
        expect(result?.metrics).toContainEqual({ label: "Low confidentiality impact", variant: "warning" });
    });

    it("decodes v4 Active Interaction", () => {
        const result = parseCvssVector("CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N");
        expect(result?.metrics).toContainEqual({ label: "Active Interaction", variant: "" });
    });
});

describe("noFixLabel", () => {
    it("explains a missing fix from the fix state", () => {
        expect(noFixLabel(undefined, "wont-fix")).toBe("won't fix");
        expect(noFixLabel(undefined, "not-fixed")).toBe("no fix yet");
    });
    it("stays silent when a fixed version exists or nothing is known", () => {
        expect(noFixLabel("1.2.3", "fixed")).toBeUndefined();
        expect(noFixLabel(undefined, "unknown")).toBeUndefined();
        expect(noFixLabel(undefined, undefined)).toBeUndefined();
    });
});
