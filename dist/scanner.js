import { readFile } from "node:fs/promises";
import path from "node:path";
import { analyzeFile } from "./analyzer.js";
import { discoverFiles } from "./discovery.js";
import { severities } from "./types.js";
export const VERSION = "0.1.1";
const defaultMaxFileSize = 1024 * 1024;
const severityRank = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1
};
function summarize(findings) {
    const counts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
    };
    for (const finding of findings) {
        counts[finding.severity] += 1;
    }
    const rawScore = counts.critical * 25 +
        counts.high * 12 +
        counts.medium * 5 +
        counts.low * 2 +
        counts.info;
    return {
        ...counts,
        total: findings.length,
        riskScore: Math.min(100, rawScore)
    };
}
export async function scanProject(root = ".", options = {}) {
    const started = performance.now();
    const startedAt = new Date().toISOString();
    const absoluteRoot = path.resolve(root);
    const files = await discoverFiles(absoluteRoot);
    const maxFileSize = options.maxFileSize ?? defaultMaxFileSize;
    const findings = [];
    let filesScanned = 0;
    for (const file of files) {
        if (file.size > maxFileSize) {
            continue;
        }
        const content = await readFile(file.absolutePath, "utf8");
        findings.push(...analyzeFile(file, content));
        filesScanned += 1;
    }
    findings.sort((a, b) => {
        const severityDifference = severityRank[b.severity] - severityRank[a.severity];
        return (severityDifference ||
            a.file.localeCompare(b.file) ||
            a.line - b.line ||
            a.ruleId.localeCompare(b.ruleId));
    });
    return {
        schemaVersion: "1.0",
        tool: {
            name: "agent-skill-aegis",
            version: VERSION
        },
        root: absoluteRoot,
        startedAt,
        durationMs: Number((performance.now() - started).toFixed(2)),
        filesScanned,
        findings,
        summary: summarize(findings)
    };
}
export function shouldFail(result, threshold) {
    if (threshold === "never") {
        return false;
    }
    const minimum = severityRank[threshold];
    return result.findings.some((finding) => severityRank[finding.severity] >= minimum);
}
export function isFailThreshold(value) {
    return value === "never" || severities.includes(value);
}
//# sourceMappingURL=scanner.js.map