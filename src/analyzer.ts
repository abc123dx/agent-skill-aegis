import { parse, printParseErrorCode, type ParseError } from "jsonc-parser";
import { makeFinding } from "./catalog.js";
import type { DiscoveredFile, Finding } from "./types.js";

interface Location {
  file: string;
  line: number;
  column: number;
}

const placeholderTerms =
  /(?:\$\{|process\.env|env:|redact|example|sample|changeme|replace[_-]?me|your[_-]|<[^>]+>|\*{3,})/i;

function locationAt(file: string, content: string, index: number): Location {
  const before = content.slice(0, Math.max(0, index));
  const lines = before.split("\n");
  return {
    file,
    line: lines.length,
    column: (lines.at(-1)?.length ?? 0) + 1
  };
}

function firstIndex(content: string, candidates: string[]): number {
  for (const candidate of candidates) {
    const quoted = content.indexOf(`"${candidate}"`);
    if (quoted >= 0) {
      return quoted;
    }
    const raw = content.indexOf(candidate);
    if (raw >= 0) {
      return raw;
    }
  }
  return 0;
}

function redact(value: string): string {
  if (value.length <= 6) {
    return "[REDACTED]";
  }
  return `${value.slice(0, 3)}…${value.slice(-2)} [REDACTED]`;
}

function linesWithOffsets(content: string): Array<{ text: string; offset: number }> {
  const result: Array<{ text: string; offset: number }> = [];
  let offset = 0;
  for (const text of content.split("\n")) {
    result.push({ text, offset });
    offset += text.length + 1;
  }
  return result;
}

function analyzeSecrets(
  file: DiscoveredFile,
  content: string,
  findings: Finding[]
): void {
  const namedSecret =
    /(?:["']?(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|secret)["']?\s*[:=]\s*["']?)([A-Za-z0-9_./+=-]{8,})/gi;
  const tokenPatterns = [
    /\b(AKIA[0-9A-Z]{16})\b/g,
    /\b(gh[pousr]_[A-Za-z0-9]{20,})\b/g,
    /\b(sk-[A-Za-z0-9_-]{20,})\b/g
  ];

  for (const { text, offset } of linesWithOffsets(content)) {
    const values: Array<{ value: string; index: number }> = [];
    namedSecret.lastIndex = 0;
    for (const match of text.matchAll(namedSecret)) {
      const value = match[1];
      if (value !== undefined && !placeholderTerms.test(value)) {
        values.push({
          value,
          index: offset + (match.index ?? 0) + match[0].indexOf(value)
        });
      }
    }
    for (const pattern of tokenPatterns) {
      pattern.lastIndex = 0;
      for (const match of text.matchAll(pattern)) {
        const value = match[1];
        if (value !== undefined && !placeholderTerms.test(value)) {
          values.push({
            value,
            index: offset + (match.index ?? 0)
          });
        }
      }
    }
    const unique = new Map(values.map((item) => [item.value, item]));
    for (const { value, index } of unique.values()) {
      findings.push(
        makeFinding(
          "AEGIS001",
          locationAt(file.relativePath, content, index),
          "A credential-like literal is embedded in this file.",
          redact(value)
        )
      );
    }
  }
}

function analyzeTextRules(
  file: DiscoveredFile,
  content: string,
  findings: Finding[]
): void {
  const patterns: Array<{
    id: Parameters<typeof makeFinding>[0];
    regex: RegExp;
    message: string;
  }> = [
    {
      id: "AEGIS003",
      regex:
        /\b(?:curl|wget)\b[^\n|;&]*(?:\||\b(?:bash|sh|zsh)\s+-c\b)[^\n]*(?:bash|sh|zsh|iex|invoke-expression)\b/gi,
      message: "Remote content appears to be executed without an integrity check."
    },
    {
      id: "AEGIS004",
      regex:
        /(?:\brm\s+-[^\n]*r[^\n]*f\s+(?:\/|\$HOME|~)\b|\bchmod\s+(?:-R\s+)?777\b|\b(?:bash|sh|zsh)\s+-c\b)/gi,
      message: "This command uses a high-risk shell execution pattern."
    },
    {
      id: "AEGIS007",
      regex:
        /\b(?:ignore|disregard|override)\s+(?:(?:all|any|the)\s+)?(?:previous|prior|system|developer)\s+(?:instructions?|messages?|prompts?)\b/gi,
      message: "The text attempts to override trusted instruction context."
    },
    {
      id: "AEGIS008",
      regex:
        /\b(?:exfiltrate|upload|transmit|send|forward)\b[^\n]{0,80}\b(?:secrets?|credentials?|tokens?|private\s+keys?|user\s+data|files?)\b/gi,
      message: "The text requests transmission of potentially sensitive data."
    },
    {
      id: "AEGIS012",
      regex:
        /\b(?:do\s+not|don't|never)\s+(?:tell|inform|notify|show|reveal\s+to)\s+(?:the\s+)?user\b|\bwithout\s+(?:the\s+)?user(?:'s)?\s+(?:knowledge|consent|approval)\b|\bsilently\s+(?:upload|send|execute|collect)\b/gi,
      message: "The text instructs the agent to conceal behavior from the user."
    }
  ];

  for (const pattern of patterns) {
    pattern.regex.lastIndex = 0;
    for (const match of content.matchAll(pattern.regex)) {
      findings.push(
        makeFinding(
          pattern.id,
          locationAt(file.relativePath, content, match.index ?? 0),
          pattern.message,
          match[0].trim().slice(0, 160)
        )
      );
    }
  }

  const insecureHttp = /\bhttp:\/\/(?!localhost\b|127\.0\.0\.1\b|\[::1\]\b)[^\s"'<>)}\]]+/gi;
  for (const match of content.matchAll(insecureHttp)) {
    findings.push(
      makeFinding(
        "AEGIS006",
        locationAt(file.relativePath, content, match.index ?? 0),
        `Remote endpoint uses clear-text HTTP: ${match[0]}`,
        match[0]
      )
    );
  }

  const npxCommand =
    /\bnpx\s+(?:(?:--yes|-y|--quiet|-q)\s+)*(@[a-z0-9_.-]+\/[a-z0-9_.-]+|[a-z0-9_.-]+)(?![@a-z0-9_.-])/gi;
  for (const match of content.matchAll(npxCommand)) {
    const packageName = match[1];
    if (packageName !== undefined) {
      findings.push(
        makeFinding(
          "AEGIS002",
          locationAt(file.relativePath, content, match.index ?? 0),
          `npx package "${packageName}" is not pinned to an exact version.`,
          match[0]
        )
      );
    }
  }

  const uvxCommand =
    /\buvx\s+(?:--quiet\s+)?([a-z0-9_.-]+)(?![a-z0-9_.-]|(?:==|@)[a-z0-9])/gi;
  for (const match of content.matchAll(uvxCommand)) {
    const packageName = match[1];
    if (packageName !== undefined) {
      findings.push(
        makeFinding(
          "AEGIS002",
          locationAt(file.relativePath, content, match.index ?? 0),
          `uvx package "${packageName}" is not pinned to an exact version.`,
          match[0]
        )
      );
    }
  }
}

function isPinned(packageSpec: string, runner: "npx" | "uvx"): boolean {
  if (
    packageSpec.startsWith(".") ||
    packageSpec.startsWith("/") ||
    packageSpec.startsWith("file:") ||
    packageSpec.startsWith("git+")
  ) {
    return true;
  }
  if (runner === "uvx" && /==[^=]/.test(packageSpec)) {
    return true;
  }
  if (packageSpec.startsWith("@")) {
    return packageSpec.lastIndexOf("@") > packageSpec.indexOf("/");
  }
  return packageSpec.includes("@");
}

function packageArgument(args: unknown[], runner: "npx" | "uvx"): string | undefined {
  const strings = args.filter((arg): arg is string => typeof arg === "string");
  for (let index = 0; index < strings.length; index += 1) {
    const value = strings[index]!;
    if (value === "--package" || value === "-p" || value === "--from") {
      index += 1;
      continue;
    }
    if (value.startsWith("-")) {
      continue;
    }
    if (runner === "npx" && ["yes", "no"].includes(value)) {
      continue;
    }
    return value;
  }
  return undefined;
}

function isBroadPath(value: string): boolean {
  const normalized = value.trim().replaceAll("\\", "/");
  return (
    normalized === "/" ||
    normalized === "~" ||
    normalized === "$HOME" ||
    normalized === "${HOME}" ||
    normalized === "%USERPROFILE%" ||
    /^[A-Za-z]:\/?$/.test(normalized) ||
    /^\/(?:Users|home)(?:\/\*|\/[^/]+)?\/?$/.test(normalized) ||
    normalized === "/etc" ||
    normalized === "/var" ||
    normalized === "**" ||
    normalized === "**/*"
  );
}

function analyzeObject(
  file: DiscoveredFile,
  content: string,
  value: unknown,
  findings: Finding[],
  pathParts: string[] = []
): void {
  if (Array.isArray(value)) {
    for (const item of value) {
      analyzeObject(file, content, item, findings, pathParts);
    }
    return;
  }
  if (value === null || typeof value !== "object") {
    return;
  }

  const record = value as Record<string, unknown>;
  const command =
    typeof record.command === "string"
      ? record.command.toLowerCase().split(/[\\/]/).at(-1)
      : undefined;
  const stringArguments = Array.isArray(record.args)
    ? record.args.filter((arg): arg is string => typeof arg === "string")
    : [];
  if ((command === "npx" || command === "uvx") && Array.isArray(record.args)) {
    const runner = command;
    const dependency = packageArgument(record.args, runner);
    if (dependency !== undefined && !isPinned(dependency, runner)) {
      const index = firstIndex(content, [dependency, String(record.command)]);
      findings.push(
        makeFinding(
          "AEGIS002",
          locationAt(file.relativePath, content, index),
          `${runner} package "${dependency}" is not pinned to an exact version.`,
          `${runner} ${dependency}`
        )
      );
    }
  }

  if (
    command !== undefined &&
    ["bash", "sh", "zsh", "powershell", "pwsh"].includes(command) &&
    stringArguments.some((argument) =>
      ["-c", "-command", "/c"].includes(argument.toLowerCase())
    )
  ) {
    const index = firstIndex(content, [String(record.command)]);
    findings.push(
      makeFinding(
        "AEGIS004",
        locationAt(file.relativePath, content, index),
        `MCP server delegates execution through ${command}.`,
        `${command} ${stringArguments.join(" ").slice(0, 120)}`
      )
    );
  }

  const context = pathParts.join(".").toLowerCase();
  const looksLikeFilesystemServer =
    context.includes("filesystem") ||
    (typeof record.command === "string" &&
      record.command.toLowerCase().includes("filesystem")) ||
    (Array.isArray(record.args) &&
      record.args.some(
        (arg) => typeof arg === "string" && arg.toLowerCase().includes("filesystem")
      ));

  for (const [key, child] of Object.entries(record)) {
    const permissionKey =
      /^(?:allowedDirectories|directories|filesystem|paths|roots|workspaceRoots)$/i.test(
        key
      );
    const candidateValues = Array.isArray(child) ? child : [child];
    if (permissionKey || (looksLikeFilesystemServer && key === "args")) {
      for (const candidate of candidateValues) {
        if (typeof candidate === "string" && isBroadPath(candidate)) {
          const index = firstIndex(content, [candidate, key]);
          findings.push(
            makeFinding(
              "AEGIS005",
              locationAt(file.relativePath, content, index),
              `Filesystem permission includes broad path "${candidate}".`,
              candidate
            )
          );
        }
      }
    }
    analyzeObject(file, content, child, findings, [...pathParts, key]);
  }
}

function analyzeTomlConfig(
  file: DiscoveredFile,
  content: string,
  findings: Finding[]
): void {
  const blocks = content.split(/(?=^\s*\[)/m);
  let searchOffset = 0;

  for (const block of blocks) {
    const blockOffset = content.indexOf(block, searchOffset);
    searchOffset = Math.max(searchOffset, blockOffset + block.length);
    const commandMatch = block.match(
      /^\s*command\s*=\s*["']([^"']+)["']/im
    );
    const argsMatch = block.match(
      /^\s*args\s*=\s*\[([\s\S]*?)\]/im
    );
    if (commandMatch === null) {
      continue;
    }

    const commandValue = commandMatch[1] ?? "";
    const command = commandValue.toLowerCase().split(/[\\/]/).at(-1);
    const rawArgs = argsMatch?.[1] ?? "";
    const args = [...rawArgs.matchAll(/["']([^"']+)["']/g)]
      .map((match) => match[1])
      .filter((value): value is string => value !== undefined);
    const locationIndex =
      Math.max(0, blockOffset) + (commandMatch.index ?? 0);

    if (command === "npx" || command === "uvx") {
      const dependency = packageArgument(args, command);
      if (dependency !== undefined && !isPinned(dependency, command)) {
        findings.push(
          makeFinding(
            "AEGIS002",
            locationAt(file.relativePath, content, locationIndex),
            `${command} package "${dependency}" is not pinned to an exact version.`,
            `${command} ${dependency}`
          )
        );
      }

      const filesystemContext = `${block} ${dependency ?? ""}`.toLowerCase();
      if (filesystemContext.includes("filesystem")) {
        for (const argument of args) {
          if (isBroadPath(argument)) {
            findings.push(
              makeFinding(
                "AEGIS005",
                locationAt(file.relativePath, content, locationIndex),
                `Filesystem permission includes broad path "${argument}".`,
                argument
              )
            );
          }
        }
      }
    }

    if (
      command !== undefined &&
      ["bash", "sh", "zsh", "powershell", "pwsh"].includes(command) &&
      args.some((argument) =>
        ["-c", "-command", "/c"].includes(argument.toLowerCase())
      )
    ) {
      findings.push(
        makeFinding(
          "AEGIS004",
          locationAt(file.relativePath, content, locationIndex),
          `MCP server delegates execution through ${command}.`,
          `${command} ${args.join(" ").slice(0, 120)}`
        )
      );
    }
  }
}

function analyzeMcpConfig(
  file: DiscoveredFile,
  content: string,
  findings: Finding[]
): void {
  if (file.relativePath.toLowerCase().endsWith(".toml")) {
    analyzeTomlConfig(file, content, findings);
    return;
  }
  const errors: ParseError[] = [];
  const data = parse(content, errors, {
    allowTrailingComma: true,
    disallowComments: false
  });
  if (errors.length > 0) {
    for (const error of errors.slice(0, 3)) {
      findings.push(
        makeFinding(
          "AEGIS011",
          locationAt(file.relativePath, content, error.offset),
          `JSON parse error: ${printParseErrorCode(error.error)}.`
        )
      );
    }
    return;
  }
  analyzeObject(file, content, data, findings);
}

function analyzeSkillMetadata(
  file: DiscoveredFile,
  content: string,
  findings: Finding[]
): void {
  const normalized = content.replace(/^\uFEFF/, "");
  const frontmatter = normalized.match(/^---\s*\n([\s\S]*?)\n---(?:\s*\n|$)/);
  if (frontmatter === null) {
    findings.push(
      makeFinding(
        "AEGIS009",
        { file: file.relativePath, line: 1, column: 1 },
        "SKILL.md has no YAML frontmatter; required fields are name and description."
      )
    );
    return;
  }

  const metadata = frontmatter[1] ?? "";
  const missing: string[] = [];
  if (!/^name\s*:\s*\S.*$/im.test(metadata)) {
    missing.push("name");
  }
  if (!/^description\s*:\s*\S.*$/im.test(metadata)) {
    missing.push("description");
  }
  if (missing.length > 0) {
    findings.push(
      makeFinding(
        "AEGIS009",
        { file: file.relativePath, line: 1, column: 1 },
        `SKILL.md frontmatter is missing: ${missing.join(", ")}.`
      )
    );
  }
}

export function analyzeFile(file: DiscoveredFile, content: string): Finding[] {
  const findings: Finding[] = [];

  if ((file.mode & 0o002) !== 0) {
    findings.push(
      makeFinding(
        "AEGIS010",
        { file: file.relativePath, line: 1, column: 1 },
        "This security-sensitive file is world-writable."
      )
    );
  }

  analyzeSecrets(file, content, findings);
  analyzeTextRules(file, content, findings);
  if (file.kind === "mcp-config") {
    analyzeMcpConfig(file, content, findings);
  } else {
    analyzeSkillMetadata(file, content, findings);
  }

  const unique = new Map<string, Finding>();
  for (const finding of findings) {
    const key = [
      finding.ruleId,
      finding.file,
      finding.line,
      finding.column,
      finding.message
    ].join(":");
    unique.set(key, finding);
  }
  return [...unique.values()];
}
