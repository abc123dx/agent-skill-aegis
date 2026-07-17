import { describe, expect, it } from "vitest";
import {
  isOutputFormat,
  renderHtml,
  renderReport,
  renderSarif,
  renderTerminal
} from "../src/reporters.js";
import type { ScanResult } from "../src/types.js";

const result: ScanResult = {
  schemaVersion: "1.0",
  tool: { name: "agent-skill-aegis", version: "0.1.0" },
  root: "/tmp/project",
  startedAt: "2026-01-01T00:00:00.000Z",
  durationMs: 12.5,
  filesScanned: 2,
  summary: {
    total: 1,
    riskScore: 25,
    critical: 1,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  },
  findings: [
    {
      ruleId: "AEGIS001",
      title: "Hard-coded credential",
      severity: "critical",
      category: "credentials",
      message: "A secret was found.",
      recommendation: "Rotate it.",
      file: ".mcp.json",
      line: 3,
      column: 8,
      evidence: "<redacted>"
    }
  ]
};

describe("reporters", () => {
  it("renders a readable terminal report without forced color", () => {
    const output = renderTerminal(result, { color: false });

    expect(output).toContain("AEGIS // MCP & AGENT SKILL SECURITY");
    expect(output).toContain(".mcp.json:3:8");
    expect(output).not.toContain("\u001B[");
  });

  it("renders valid machine-readable JSON", () => {
    const output = renderReport(result, "json");

    expect(JSON.parse(output)).toMatchObject({
      schemaVersion: "1.0",
      summary: { critical: 1 }
    });
  });

  it("renders escaped, filterable standalone HTML", () => {
    const output = renderHtml(result);

    expect(output).toContain("<!doctype html>");
    expect(output).toContain('data-filter="critical"');
    expect(output).toContain("&lt;redacted&gt;");
    expect(output).not.toContain("<redacted>");
  });

  it("renders SARIF 2.1.0 with physical locations and rule metadata", () => {
    const sarif = JSON.parse(renderSarif(result));

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].tool.driver.rules[0].id).toBe("AEGIS001");
    expect(
      sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine
    ).toBe(3);
  });

  it("validates output formats", () => {
    expect(isOutputFormat("sarif")).toBe(true);
    expect(isOutputFormat("xml")).toBe(false);
  });
});
