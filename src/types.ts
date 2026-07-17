export const severities = [
  "critical",
  "high",
  "medium",
  "low",
  "info"
] as const;

export type Severity = (typeof severities)[number];
export type FailThreshold = Severity | "never";
export type OutputFormat = "terminal" | "json" | "html" | "sarif";
export type FileKind = "mcp-config" | "skill";

export interface DiscoveredFile {
  absolutePath: string;
  relativePath: string;
  kind: FileKind;
  mode: number;
  size: number;
}

export interface Finding {
  ruleId: string;
  title: string;
  severity: Severity;
  category:
    | "credentials"
    | "dependency"
    | "execution"
    | "metadata"
    | "parsing"
    | "permissions"
    | "prompt-safety"
    | "transport";
  message: string;
  recommendation: string;
  file: string;
  line: number;
  column: number;
  evidence?: string;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanSummary extends SeverityCounts {
  total: number;
  riskScore: number;
}

export interface ScanResult {
  schemaVersion: "1.0";
  tool: {
    name: "agent-skill-aegis";
    version: string;
  };
  root: string;
  startedAt: string;
  durationMs: number;
  filesScanned: number;
  findings: Finding[];
  summary: ScanSummary;
}

export interface ScanOptions {
  maxFileSize?: number;
}
