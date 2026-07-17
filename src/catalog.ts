import type { Finding, Severity } from "./types.js";

export interface RuleDefinition {
  id: string;
  title: string;
  severity: Severity;
  category: Finding["category"];
  description: string;
  recommendation: string;
}

export const rules = {
  AEGIS001: {
    id: "AEGIS001",
    title: "Hard-coded credential",
    severity: "critical",
    category: "credentials",
    description: "A credential-like value is stored directly in a scanned file.",
    recommendation:
      "Remove the value from version control, rotate it, and reference an environment variable or secret manager."
  },
  AEGIS002: {
    id: "AEGIS002",
    title: "Unpinned executable dependency",
    severity: "high",
    category: "dependency",
    description: "npx or uvx may resolve a different package version on each run.",
    recommendation:
      "Pin the exact package version (for example package@1.2.3 or package==1.2.3) and review lock or provenance data."
  },
  AEGIS003: {
    id: "AEGIS003",
    title: "Downloaded content is executed",
    severity: "critical",
    category: "execution",
    description: "Remote content is piped or passed directly to an interpreter.",
    recommendation:
      "Download to a file, verify its digest or signature, inspect it, and only then execute the trusted artifact."
  },
  AEGIS004: {
    id: "AEGIS004",
    title: "Dangerous shell execution",
    severity: "high",
    category: "execution",
    description: "A shell command can perform broad or difficult-to-review actions.",
    recommendation:
      "Use a narrowly scoped executable and argument list. Remove recursive deletion, permissive chmod, and shell indirection."
  },
  AEGIS005: {
    id: "AEGIS005",
    title: "Over-broad filesystem access",
    severity: "high",
    category: "permissions",
    description: "A server or skill appears able to access a filesystem root or an entire user home.",
    recommendation:
      "Grant access only to the smallest project-specific read/write directories required by the tool."
  },
  AEGIS006: {
    id: "AEGIS006",
    title: "Insecure remote transport",
    severity: "medium",
    category: "transport",
    description: "A non-local endpoint uses clear-text HTTP.",
    recommendation:
      "Use HTTPS with certificate verification, or bind the endpoint to loopback when it is intentionally local."
  },
  AEGIS007: {
    id: "AEGIS007",
    title: "Prompt-injection instruction",
    severity: "high",
    category: "prompt-safety",
    description: "Instruction text attempts to override higher-priority or prior instructions.",
    recommendation:
      "Remove instruction-precedence manipulation and explicitly scope the skill's allowed behavior."
  },
  AEGIS008: {
    id: "AEGIS008",
    title: "Potential data exfiltration instruction",
    severity: "critical",
    category: "prompt-safety",
    description: "Instruction text requests covert disclosure or transmission of sensitive data.",
    recommendation:
      "Remove covert transmission behavior. Require explicit user approval, destination allowlists, and data minimization."
  },
  AEGIS009: {
    id: "AEGIS009",
    title: "Missing Agent Skill metadata",
    severity: "medium",
    category: "metadata",
    description: "SKILL.md lacks required frontmatter or identifying fields.",
    recommendation:
      "Add YAML frontmatter with a stable name and a precise description of the skill's purpose and boundaries."
  },
  AEGIS010: {
    id: "AEGIS010",
    title: "World-writable security file",
    severity: "medium",
    category: "permissions",
    description: "A scanned configuration or skill can be modified by any local user.",
    recommendation:
      "Remove world-write permission (for example, chmod o-w) and verify file ownership."
  },
  AEGIS011: {
    id: "AEGIS011",
    title: "Invalid MCP configuration",
    severity: "high",
    category: "parsing",
    description: "An MCP JSON or JSONC configuration could not be parsed.",
    recommendation:
      "Correct the reported JSON syntax error before loading the configuration into an agent host."
  },
  AEGIS012: {
    id: "AEGIS012",
    title: "Concealed behavior instruction",
    severity: "high",
    category: "prompt-safety",
    description: "Instruction text tells the agent to hide an action from the user.",
    recommendation:
      "Make all consequential behavior visible and require informed user approval."
  }
} as const satisfies Record<string, RuleDefinition>;

export type RuleId = keyof typeof rules;

export function makeFinding(
  id: RuleId,
  location: Pick<Finding, "file" | "line" | "column">,
  message: string,
  evidence?: string
): Finding {
  const rule = rules[id];
  return {
    ...location,
    ruleId: rule.id,
    title: rule.title,
    severity: rule.severity,
    category: rule.category,
    message,
    recommendation: rule.recommendation,
    ...(evidence === undefined ? {} : { evidence })
  };
}
