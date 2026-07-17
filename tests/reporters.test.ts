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
  tool: { name: "agent-skill-aegis", version: "0.1.1" },
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
      title: "硬编码凭据",
      severity: "critical",
      category: "credentials",
      message: "发现一个密钥。",
      recommendation: "立即轮换。",
      file: ".mcp.json",
      line: 3,
      column: 8,
      evidence: "<redacted>"
    }
  ]
};

describe("报告器", () => {
  it("渲染不强制使用颜色的可读中文终端报告", () => {
    const output = renderTerminal(result, { color: false });

    expect(output).toContain("AEGIS // MCP 与 AGENT SKILL 安全审计");
    expect(output).toContain("硬编码凭据");
    expect(output).toContain(".mcp.json:3:8");
    expect(output).not.toContain("\u001B[");
  });

  it("渲染有效的机器可读 JSON", () => {
    const output = renderReport(result, "json");

    expect(JSON.parse(output)).toMatchObject({
      schemaVersion: "1.0",
      summary: { critical: 1 }
    });
  });

  it("渲染已转义、可筛选的中文独立 HTML", () => {
    const output = renderHtml(result);

    expect(output).toContain("<!doctype html>");
    expect(output).toContain('<html lang="zh-CN">');
    expect(output).toContain("安全态势");
    expect(output).toContain('data-filter="critical"');
    expect(output).toContain("&lt;redacted&gt;");
    expect(output).not.toContain("<redacted>");
  });

  it("渲染包含物理位置与规则元数据的 SARIF 2.1.0", () => {
    const sarif = JSON.parse(renderSarif(result));

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].tool.driver.rules[0].id).toBe("AEGIS001");
    expect(
      sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine
    ).toBe(3);
  });

  it("验证输出格式", () => {
    expect(isOutputFormat("sarif")).toBe(true);
    expect(isOutputFormat("xml")).toBe(false);
  });
});
