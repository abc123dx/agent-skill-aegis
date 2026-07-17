import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  isFailThreshold,
  scanProject,
  shouldFail
} from "../src/scanner.js";

const vulnerable = fileURLToPath(
  new URL("../examples/vulnerable", import.meta.url)
);
const safe = fileURLToPath(new URL("../examples/safe", import.meta.url));

describe("scanProject", () => {
  it("finds every advertised risk family in the vulnerable fixture", async () => {
    const result = await scanProject(vulnerable);
    const ids = new Set(result.findings.map((finding) => finding.ruleId));

    expect(result.filesScanned).toBe(2);
    expect(ids).toEqual(
      expect.objectContaining(
        new Set([
          "AEGIS001",
          "AEGIS002",
          "AEGIS003",
          "AEGIS004",
          "AEGIS005",
          "AEGIS006",
          "AEGIS007",
          "AEGIS008",
          "AEGIS009",
          "AEGIS012"
        ])
      )
    );
    expect(result.summary.critical).toBeGreaterThan(0);
    expect(result.summary.riskScore).toBeGreaterThan(50);
  });

  it("keeps the safe fixture free of findings", async () => {
    const result = await scanProject(safe);

    expect(result.filesScanned).toBe(2);
    expect(result.findings).toEqual([]);
    expect(result.summary.riskScore).toBe(0);
  });

  it("applies severity failure thresholds", async () => {
    const result = await scanProject(vulnerable);

    expect(shouldFail(result, "critical")).toBe(true);
    expect(shouldFail(result, "never")).toBe(false);
  });

  it("validates threshold names", () => {
    expect(isFailThreshold("medium")).toBe(true);
    expect(isFailThreshold("never")).toBe(true);
    expect(isFailThreshold("banana")).toBe(false);
  });
});
