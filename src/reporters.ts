import path from "node:path";
import { rules } from "./catalog.js";
import type {
  Finding,
  OutputFormat,
  ScanResult,
  Severity
} from "./types.js";

const ansi = {
  reset: "\u001B[0m",
  bold: "\u001B[1m",
  dim: "\u001B[2m",
  cyan: "\u001B[36m",
  green: "\u001B[32m",
  yellow: "\u001B[33m",
  red: "\u001B[31m",
  magenta: "\u001B[35m"
};

const severityLabels: Record<Severity, string> = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
  info: "信息"
};

const sarifRuleNames: Record<keyof typeof rules, string> = {
  AEGIS001: "Hardcodedcredential",
  AEGIS002: "Unpinnedexecutabledependency",
  AEGIS003: "Downloadedcontentisexecuted",
  AEGIS004: "Dangerousshellexecution",
  AEGIS005: "Overbroadfilesystemaccess",
  AEGIS006: "Insecureremotetransport",
  AEGIS007: "Promptinjectioninstruction",
  AEGIS008: "Potentialdataexfiltrationinstruction",
  AEGIS009: "MissingAgentSkillmetadata",
  AEGIS010: "Worldwritablesecurityfile",
  AEGIS011: "InvalidMCPconfiguration",
  AEGIS012: "Concealedbehaviorinstruction"
};

function paint(text: string, code: string, enabled: boolean): string {
  return enabled ? `${code}${text}${ansi.reset}` : text;
}

function severityColor(severity: Severity): string {
  switch (severity) {
    case "critical":
      return ansi.magenta;
    case "high":
      return ansi.red;
    case "medium":
      return ansi.yellow;
    case "low":
      return ansi.cyan;
    case "info":
      return ansi.dim;
  }
}

export function renderTerminal(
  result: ScanResult,
  options: { color?: boolean } = {}
): string {
  const color = options.color ?? true;
  const summaryItems: Array<[string, number, Severity]> = [
    ["严重", result.summary.critical, "critical"],
    ["高危", result.summary.high, "high"],
    ["中危", result.summary.medium, "medium"],
    ["低危", result.summary.low, "low"],
    ["信息", result.summary.info, "info"]
  ];
  const output: string[] = [
    "",
    paint("  AEGIS // MCP 与 AGENT SKILL 安全审计", ansi.bold + ansi.cyan, color),
    paint(
      `  ${result.filesScanned} 个文件 · ${result.durationMs} 毫秒 · 风险 ${result.summary.riskScore}/100`,
      ansi.dim,
      color
    ),
    "",
    summaryItems
      .map(([label, count, severity]) =>
        paint(`${label} ${count}`, severityColor(severity), color)
      )
      .join("  "),
    ""
  ];

  if (result.findings.length === 0) {
    output.push(
      paint("  ✓ 未发现确定性安全问题。", ansi.green, color),
      ""
    );
    return output.join("\n");
  }

  for (const finding of result.findings) {
    const badge = paint(
      severityLabels[finding.severity].padEnd(4),
      severityColor(finding.severity),
      color
    );
    output.push(
      `  ${badge} ${paint(finding.ruleId, ansi.bold, color)} ${finding.title}`,
      `           ${paint(`${finding.file}:${finding.line}:${finding.column}`, ansi.cyan, color)}`,
      `           ${finding.message}`,
      `           ${paint(`修复：${finding.recommendation}`, ansi.dim, color)}`,
      ""
    );
  }

  return output.join("\n");
}

function escapeHtml(value: unknown): string {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function findingCard(finding: Finding): string {
  return `<article class="finding" data-severity="${finding.severity}">
  <div class="finding-head">
    <span class="severity ${finding.severity}">${severityLabels[finding.severity]}</span>
    <code>${escapeHtml(finding.ruleId)}</code>
    <strong>${escapeHtml(finding.title)}</strong>
  </div>
  <div class="location">${escapeHtml(finding.file)}:${finding.line}:${finding.column}</div>
  <p>${escapeHtml(finding.message)}</p>
  ${
    finding.evidence === undefined
      ? ""
      : `<pre>${escapeHtml(finding.evidence)}</pre>`
  }
  <p class="fix"><b>修复建议</b> ${escapeHtml(finding.recommendation)}</p>
</article>`;
}

export function renderHtml(result: ScanResult): string {
  const cards =
    result.findings.length === 0
      ? '<div class="empty">✓ 未发现确定性安全问题。</div>'
      : result.findings.map(findingCard).join("\n");
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Agent Skill Aegis · 安全报告</title>
  <style>
    :root{color-scheme:dark;--bg:#07111f;--panel:#0d1a2b;--line:#203551;--text:#eaf2ff;--muted:#8da4bf;--cyan:#45d7ff;--critical:#e879f9;--high:#ff6b81;--medium:#ffd166;--low:#55d6be;--info:#8da4bf}
    *{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 80% 0,#14305a 0,transparent 38%),var(--bg);color:var(--text);font:15px/1.6 Inter,ui-sans-serif,system-ui,sans-serif}main{max-width:1080px;margin:auto;padding:56px 24px 80px}.eyebrow{color:var(--cyan);font:700 12px/1.2 ui-monospace,monospace;letter-spacing:.18em}.hero{display:flex;justify-content:space-between;gap:24px;align-items:end;margin:16px 0 38px}.hero h1{font-size:clamp(34px,6vw,68px);line-height:1;margin:0;letter-spacing:-.055em}.risk{min-width:150px;text-align:right}.risk b{display:block;color:var(--cyan);font-size:46px;line-height:1}.muted,.location{color:var(--muted)}.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:24px 0 36px}.stat{padding:17px;border:1px solid var(--line);border-radius:14px;background:#0d1a2bcc}.stat b{display:block;font-size:28px}.filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:18px}button{border:1px solid var(--line);border-radius:999px;background:var(--panel);color:var(--text);padding:8px 13px;cursor:pointer}button:hover,button.active{border-color:var(--cyan);color:var(--cyan)}.finding{border:1px solid var(--line);border-radius:16px;background:linear-gradient(140deg,#0e1d30,#0a1625);padding:20px;margin:12px 0;box-shadow:0 14px 40px #0003}.finding-head{display:flex;align-items:center;gap:11px}.severity{border:1px solid currentColor;border-radius:999px;padding:2px 8px;font:700 11px ui-monospace,monospace;text-transform:uppercase}.critical{color:var(--critical)}.high{color:var(--high)}.medium{color:var(--medium)}.low{color:var(--low)}.info{color:var(--info)}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.location{font:13px ui-monospace,monospace;margin-top:8px}pre{overflow:auto;padding:10px 12px;border-radius:8px;background:#050c16;color:#aac4e3}.fix{padding-top:12px;border-top:1px solid var(--line)}.fix b{color:var(--cyan);margin-right:8px}.empty{padding:40px;text-align:center;border:1px solid #286958;border-radius:16px;background:#0c2923;color:#66e0bd}footer{margin-top:34px;color:var(--muted);font-size:13px}@media(max-width:700px){.hero{align-items:start;flex-direction:column}.risk{text-align:left}.stats{grid-template-columns:repeat(2,1fr)}}
  </style>
</head>
<body>
<main>
  <div class="eyebrow">AGENT SKILL AEGIS // 确定性安全审计</div>
  <section class="hero">
    <div><h1>安全态势<br>审计报告</h1><p class="muted">${escapeHtml(result.root)} · 已扫描 ${result.filesScanned} 个文件</p></div>
    <div class="risk"><b>${result.summary.riskScore}</b><span class="muted">风险评分 / 100</span></div>
  </section>
  <section class="stats">
    ${(["critical", "high", "medium", "low", "info"] as const)
      .map(
        (severity) =>
          `<div class="stat ${severity}"><span>${severityLabels[severity]}</span><b>${result.summary[severity]}</b></div>`
      )
      .join("")}
  </section>
  <nav class="filters" aria-label="问题筛选">
    <button class="active" data-filter="all">全部 ${result.summary.total}</button>
    ${(["critical", "high", "medium", "low", "info"] as const)
      .map(
        (severity) =>
          `<button data-filter="${severity}">${severityLabels[severity]} ${result.summary[severity]}</button>`
      )
      .join("")}
  </nav>
  <section id="findings">${cards}</section>
  <footer>由 agent-skill-aegis ${escapeHtml(result.tool.version)} 于 ${escapeHtml(result.startedAt)} 生成 · 源代码与扫描结果均未离开本机。</footer>
</main>
<script>
document.querySelectorAll('button[data-filter]').forEach(button=>button.addEventListener('click',()=>{
  document.querySelectorAll('button').forEach(item=>item.classList.remove('active'));
  button.classList.add('active');
  document.querySelectorAll('.finding').forEach(card=>{
    card.hidden=button.dataset.filter!=='all'&&card.dataset.severity!==button.dataset.filter;
  });
}));
</script>
</body>
</html>`;
}

function sarifLevel(severity: Severity): "error" | "warning" | "note" {
  if (severity === "critical" || severity === "high") {
    return "error";
  }
  if (severity === "medium") {
    return "warning";
  }
  return "note";
}

export function renderSarif(result: ScanResult): string {
  const usedRuleIds = [...new Set(result.findings.map((item) => item.ruleId))];
  const sarif = {
    $schema:
      "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: result.tool.name,
            version: result.tool.version,
            informationUri:
              "https://github.com/abc123dx/agent-skill-aegis",
            rules: usedRuleIds.map((id) => {
              const rule = rules[id as keyof typeof rules];
              return {
                id: rule.id,
                name: sarifRuleNames[id as keyof typeof rules],
                shortDescription: { text: rule.title },
                fullDescription: { text: rule.description },
                help: {
                  text: rule.recommendation,
                  markdown: `**修复建议：**${rule.recommendation}`
                },
                properties: {
                  category: rule.category,
                  defaultSeverity: rule.severity,
                  tags: ["security", "mcp", "agent-skills", rule.category]
                }
              };
            })
          }
        },
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: new Date(
              new Date(result.startedAt).getTime() + result.durationMs
            ).toISOString()
          }
        ],
        results: result.findings.map((finding) => ({
          ruleId: finding.ruleId,
          level: sarifLevel(finding.severity),
          message: { text: `${finding.title}: ${finding.message}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: finding.file.split(path.sep).join("/"),
                  uriBaseId: "%SRCROOT%"
                },
                region: {
                  startLine: finding.line,
                  startColumn: finding.column
                }
              }
            }
          ],
          properties: {
            category: finding.category,
            severity: finding.severity,
            ...(finding.evidence === undefined
              ? {}
              : { evidence: finding.evidence })
          }
        }))
      }
    ]
  };
  return `${JSON.stringify(sarif, null, 2)}\n`;
}

export function renderReport(
  result: ScanResult,
  format: OutputFormat,
  options: { color?: boolean } = {}
): string {
  switch (format) {
    case "terminal":
      return renderTerminal(result, options);
    case "json":
      return `${JSON.stringify(result, null, 2)}\n`;
    case "html":
      return renderHtml(result);
    case "sarif":
      return renderSarif(result);
  }
}

export function isOutputFormat(value: string): value is OutputFormat {
  return ["terminal", "json", "html", "sarif"].includes(value);
}
