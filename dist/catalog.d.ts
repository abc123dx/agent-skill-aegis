import type { Finding, Severity } from "./types.js";
export interface RuleDefinition {
    id: string;
    title: string;
    severity: Severity;
    category: Finding["category"];
    description: string;
    recommendation: string;
}
export declare const rules: {
    readonly AEGIS001: {
        readonly id: "AEGIS001";
        readonly title: "Hard-coded credential";
        readonly severity: "critical";
        readonly category: "credentials";
        readonly description: "A credential-like value is stored directly in a scanned file.";
        readonly recommendation: "Remove the value from version control, rotate it, and reference an environment variable or secret manager.";
    };
    readonly AEGIS002: {
        readonly id: "AEGIS002";
        readonly title: "Unpinned executable dependency";
        readonly severity: "high";
        readonly category: "dependency";
        readonly description: "npx or uvx may resolve a different package version on each run.";
        readonly recommendation: "Pin the exact package version (for example package@1.2.3 or package==1.2.3) and review lock or provenance data.";
    };
    readonly AEGIS003: {
        readonly id: "AEGIS003";
        readonly title: "Downloaded content is executed";
        readonly severity: "critical";
        readonly category: "execution";
        readonly description: "Remote content is piped or passed directly to an interpreter.";
        readonly recommendation: "Download to a file, verify its digest or signature, inspect it, and only then execute the trusted artifact.";
    };
    readonly AEGIS004: {
        readonly id: "AEGIS004";
        readonly title: "Dangerous shell execution";
        readonly severity: "high";
        readonly category: "execution";
        readonly description: "A shell command can perform broad or difficult-to-review actions.";
        readonly recommendation: "Use a narrowly scoped executable and argument list. Remove recursive deletion, permissive chmod, and shell indirection.";
    };
    readonly AEGIS005: {
        readonly id: "AEGIS005";
        readonly title: "Over-broad filesystem access";
        readonly severity: "high";
        readonly category: "permissions";
        readonly description: "A server or skill appears able to access a filesystem root or an entire user home.";
        readonly recommendation: "Grant access only to the smallest project-specific read/write directories required by the tool.";
    };
    readonly AEGIS006: {
        readonly id: "AEGIS006";
        readonly title: "Insecure remote transport";
        readonly severity: "medium";
        readonly category: "transport";
        readonly description: "A non-local endpoint uses clear-text HTTP.";
        readonly recommendation: "Use HTTPS with certificate verification, or bind the endpoint to loopback when it is intentionally local.";
    };
    readonly AEGIS007: {
        readonly id: "AEGIS007";
        readonly title: "Prompt-injection instruction";
        readonly severity: "high";
        readonly category: "prompt-safety";
        readonly description: "Instruction text attempts to override higher-priority or prior instructions.";
        readonly recommendation: "Remove instruction-precedence manipulation and explicitly scope the skill's allowed behavior.";
    };
    readonly AEGIS008: {
        readonly id: "AEGIS008";
        readonly title: "Potential data exfiltration instruction";
        readonly severity: "critical";
        readonly category: "prompt-safety";
        readonly description: "Instruction text requests covert disclosure or transmission of sensitive data.";
        readonly recommendation: "Remove covert transmission behavior. Require explicit user approval, destination allowlists, and data minimization.";
    };
    readonly AEGIS009: {
        readonly id: "AEGIS009";
        readonly title: "Missing Agent Skill metadata";
        readonly severity: "medium";
        readonly category: "metadata";
        readonly description: "SKILL.md lacks required frontmatter or identifying fields.";
        readonly recommendation: "Add YAML frontmatter with a stable name and a precise description of the skill's purpose and boundaries.";
    };
    readonly AEGIS010: {
        readonly id: "AEGIS010";
        readonly title: "World-writable security file";
        readonly severity: "medium";
        readonly category: "permissions";
        readonly description: "A scanned configuration or skill can be modified by any local user.";
        readonly recommendation: "Remove world-write permission (for example, chmod o-w) and verify file ownership.";
    };
    readonly AEGIS011: {
        readonly id: "AEGIS011";
        readonly title: "Invalid MCP configuration";
        readonly severity: "high";
        readonly category: "parsing";
        readonly description: "An MCP JSON or JSONC configuration could not be parsed.";
        readonly recommendation: "Correct the reported JSON syntax error before loading the configuration into an agent host.";
    };
    readonly AEGIS012: {
        readonly id: "AEGIS012";
        readonly title: "Concealed behavior instruction";
        readonly severity: "high";
        readonly category: "prompt-safety";
        readonly description: "Instruction text tells the agent to hide an action from the user.";
        readonly recommendation: "Make all consequential behavior visible and require informed user approval.";
    };
};
export type RuleId = keyof typeof rules;
export declare function makeFinding(id: RuleId, location: Pick<Finding, "file" | "line" | "column">, message: string, evidence?: string): Finding;
//# sourceMappingURL=catalog.d.ts.map