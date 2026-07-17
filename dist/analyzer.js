import { parse, printParseErrorCode } from "jsonc-parser";
import { makeFinding } from "./catalog.js";
const placeholderTerms = /(?:\$\{|process\.env|env:|redact|example|sample|changeme|replace[_-]?me|your[_-]|<[^>]+>|\*{3,})/i;
function locationAt(file, content, index) {
    const before = content.slice(0, Math.max(0, index));
    const lines = before.split("\n");
    return {
        file,
        line: lines.length,
        column: (lines.at(-1)?.length ?? 0) + 1
    };
}
function firstIndex(content, candidates) {
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
function redact(value) {
    if (value.length <= 6) {
        return "[已脱敏]";
    }
    return `${value.slice(0, 3)}…${value.slice(-2)} [已脱敏]`;
}
function linesWithOffsets(content) {
    const result = [];
    let offset = 0;
    for (const text of content.split("\n")) {
        result.push({ text, offset });
        offset += text.length + 1;
    }
    return result;
}
function analyzeSecrets(file, content, findings) {
    const namedSecret = /(?:["']?(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|secret)["']?\s*[:=]\s*["']?)([A-Za-z0-9_./+=-]{8,})/gi;
    const tokenPatterns = [
        /\b(AKIA[0-9A-Z]{16})\b/g,
        /\b(gh[pousr]_[A-Za-z0-9]{20,})\b/g,
        /\b(sk-[A-Za-z0-9_-]{20,})\b/g
    ];
    for (const { text, offset } of linesWithOffsets(content)) {
        const values = [];
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
            findings.push(makeFinding("AEGIS001", locationAt(file.relativePath, content, index), "此文件中嵌入了疑似凭据的字面量。", redact(value)));
        }
    }
}
function analyzeTextRules(file, content, findings) {
    const patterns = [
        {
            id: "AEGIS003",
            regex: /\b(?:curl|wget)\b[^\n|;&]*(?:\||\b(?:bash|sh|zsh)\s+-c\b)[^\n]*(?:bash|sh|zsh|iex|invoke-expression)\b/gi,
            message: "远程内容似乎在未经完整性校验的情况下被执行。"
        },
        {
            id: "AEGIS004",
            regex: /(?:\brm\s+-[^\n]*r[^\n]*f\s+(?:\/|\$HOME|~)\b|\bchmod\s+(?:-R\s+)?777\b|\b(?:bash|sh|zsh)\s+-c\b)/gi,
            message: "此命令使用了高风险的 Shell 执行模式。"
        },
        {
            id: "AEGIS007",
            regex: /\b(?:ignore|disregard|override)\s+(?:(?:all|any|the)\s+)?(?:previous|prior|system|developer)\s+(?:instructions?|messages?|prompts?)\b/gi,
            message: "文本试图覆盖可信的指令上下文。"
        },
        {
            id: "AEGIS008",
            regex: /\b(?:exfiltrate|upload|transmit|send|forward)\b[^\n]{0,80}\b(?:secrets?|credentials?|tokens?|private\s+keys?|user\s+data|files?)\b/gi,
            message: "文本要求传输可能包含敏感信息的数据。"
        },
        {
            id: "AEGIS012",
            regex: /\b(?:do\s+not|don't|never)\s+(?:tell|inform|notify|show|reveal\s+to)\s+(?:the\s+)?user\b|\bwithout\s+(?:the\s+)?user(?:'s)?\s+(?:knowledge|consent|approval)\b|\bsilently\s+(?:upload|send|execute|collect)\b/gi,
            message: "文本要求 Agent 向用户隐瞒行为。"
        }
    ];
    for (const pattern of patterns) {
        pattern.regex.lastIndex = 0;
        for (const match of content.matchAll(pattern.regex)) {
            findings.push(makeFinding(pattern.id, locationAt(file.relativePath, content, match.index ?? 0), pattern.message, match[0].trim().slice(0, 160)));
        }
    }
    const insecureHttp = /\bhttp:\/\/(?!localhost\b|127\.0\.0\.1\b|\[::1\]\b)[^\s"'<>)}\]]+/gi;
    for (const match of content.matchAll(insecureHttp)) {
        findings.push(makeFinding("AEGIS006", locationAt(file.relativePath, content, match.index ?? 0), `远程端点使用明文 HTTP：${match[0]}`, match[0]));
    }
    const npxCommand = /\bnpx\s+(?:(?:--yes|-y|--quiet|-q)\s+)*(@[a-z0-9_.-]+\/[a-z0-9_.-]+|[a-z0-9_.-]+)(?![@a-z0-9_.-])/gi;
    for (const match of content.matchAll(npxCommand)) {
        const packageName = match[1];
        if (packageName !== undefined) {
            findings.push(makeFinding("AEGIS002", locationAt(file.relativePath, content, match.index ?? 0), `npx 软件包“${packageName}”未锁定到精确版本。`, match[0]));
        }
    }
    const uvxCommand = /\buvx\s+(?:--quiet\s+)?([a-z0-9_.-]+)(?![a-z0-9_.-]|(?:==|@)[a-z0-9])/gi;
    for (const match of content.matchAll(uvxCommand)) {
        const packageName = match[1];
        if (packageName !== undefined) {
            findings.push(makeFinding("AEGIS002", locationAt(file.relativePath, content, match.index ?? 0), `uvx 软件包“${packageName}”未锁定到精确版本。`, match[0]));
        }
    }
}
function isPinned(packageSpec, runner) {
    if (packageSpec.startsWith(".") ||
        packageSpec.startsWith("/") ||
        packageSpec.startsWith("file:") ||
        packageSpec.startsWith("git+")) {
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
function packageArgument(args, runner) {
    const strings = args.filter((arg) => typeof arg === "string");
    for (let index = 0; index < strings.length; index += 1) {
        const value = strings[index];
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
function isBroadPath(value) {
    const normalized = value.trim().replaceAll("\\", "/");
    return (normalized === "/" ||
        normalized === "~" ||
        normalized === "$HOME" ||
        normalized === "${HOME}" ||
        normalized === "%USERPROFILE%" ||
        /^[A-Za-z]:\/?$/.test(normalized) ||
        /^\/(?:Users|home)(?:\/\*|\/[^/]+)?\/?$/.test(normalized) ||
        normalized === "/etc" ||
        normalized === "/var" ||
        normalized === "**" ||
        normalized === "**/*");
}
function analyzeObject(file, content, value, findings, pathParts = []) {
    if (Array.isArray(value)) {
        for (const item of value) {
            analyzeObject(file, content, item, findings, pathParts);
        }
        return;
    }
    if (value === null || typeof value !== "object") {
        return;
    }
    const record = value;
    const command = typeof record.command === "string"
        ? record.command.toLowerCase().split(/[\\/]/).at(-1)
        : undefined;
    const stringArguments = Array.isArray(record.args)
        ? record.args.filter((arg) => typeof arg === "string")
        : [];
    if ((command === "npx" || command === "uvx") && Array.isArray(record.args)) {
        const runner = command;
        const dependency = packageArgument(record.args, runner);
        if (dependency !== undefined && !isPinned(dependency, runner)) {
            const index = firstIndex(content, [dependency, String(record.command)]);
            findings.push(makeFinding("AEGIS002", locationAt(file.relativePath, content, index), `${runner} 软件包“${dependency}”未锁定到精确版本。`, `${runner} ${dependency}`));
        }
    }
    if (command !== undefined &&
        ["bash", "sh", "zsh", "powershell", "pwsh"].includes(command) &&
        stringArguments.some((argument) => ["-c", "-command", "/c"].includes(argument.toLowerCase()))) {
        const index = firstIndex(content, [String(record.command)]);
        findings.push(makeFinding("AEGIS004", locationAt(file.relativePath, content, index), `MCP 服务器通过 ${command} 委托执行。`, `${command} ${stringArguments.join(" ").slice(0, 120)}`));
    }
    const context = pathParts.join(".").toLowerCase();
    const looksLikeFilesystemServer = context.includes("filesystem") ||
        (typeof record.command === "string" &&
            record.command.toLowerCase().includes("filesystem")) ||
        (Array.isArray(record.args) &&
            record.args.some((arg) => typeof arg === "string" && arg.toLowerCase().includes("filesystem")));
    for (const [key, child] of Object.entries(record)) {
        const permissionKey = /^(?:allowedDirectories|directories|filesystem|paths|roots|workspaceRoots)$/i.test(key);
        const candidateValues = Array.isArray(child) ? child : [child];
        if (permissionKey || (looksLikeFilesystemServer && key === "args")) {
            for (const candidate of candidateValues) {
                if (typeof candidate === "string" && isBroadPath(candidate)) {
                    const index = firstIndex(content, [candidate, key]);
                    findings.push(makeFinding("AEGIS005", locationAt(file.relativePath, content, index), `文件系统权限包含范围过宽的路径“${candidate}”。`, candidate));
                }
            }
        }
        analyzeObject(file, content, child, findings, [...pathParts, key]);
    }
}
function analyzeTomlConfig(file, content, findings) {
    const blocks = content.split(/(?=^\s*\[)/m);
    let searchOffset = 0;
    for (const block of blocks) {
        const blockOffset = content.indexOf(block, searchOffset);
        searchOffset = Math.max(searchOffset, blockOffset + block.length);
        const commandMatch = block.match(/^\s*command\s*=\s*["']([^"']+)["']/im);
        const argsMatch = block.match(/^\s*args\s*=\s*\[([\s\S]*?)\]/im);
        if (commandMatch === null) {
            continue;
        }
        const commandValue = commandMatch[1] ?? "";
        const command = commandValue.toLowerCase().split(/[\\/]/).at(-1);
        const rawArgs = argsMatch?.[1] ?? "";
        const args = [...rawArgs.matchAll(/["']([^"']+)["']/g)]
            .map((match) => match[1])
            .filter((value) => value !== undefined);
        const locationIndex = Math.max(0, blockOffset) + (commandMatch.index ?? 0);
        if (command === "npx" || command === "uvx") {
            const dependency = packageArgument(args, command);
            if (dependency !== undefined && !isPinned(dependency, command)) {
                findings.push(makeFinding("AEGIS002", locationAt(file.relativePath, content, locationIndex), `${command} 软件包“${dependency}”未锁定到精确版本。`, `${command} ${dependency}`));
            }
            const filesystemContext = `${block} ${dependency ?? ""}`.toLowerCase();
            if (filesystemContext.includes("filesystem")) {
                for (const argument of args) {
                    if (isBroadPath(argument)) {
                        findings.push(makeFinding("AEGIS005", locationAt(file.relativePath, content, locationIndex), `文件系统权限包含范围过宽的路径“${argument}”。`, argument));
                    }
                }
            }
        }
        if (command !== undefined &&
            ["bash", "sh", "zsh", "powershell", "pwsh"].includes(command) &&
            args.some((argument) => ["-c", "-command", "/c"].includes(argument.toLowerCase()))) {
            findings.push(makeFinding("AEGIS004", locationAt(file.relativePath, content, locationIndex), `MCP 服务器通过 ${command} 委托执行。`, `${command} ${args.join(" ").slice(0, 120)}`));
        }
    }
}
function analyzeMcpConfig(file, content, findings) {
    if (file.relativePath.toLowerCase().endsWith(".toml")) {
        analyzeTomlConfig(file, content, findings);
        return;
    }
    const errors = [];
    const data = parse(content, errors, {
        allowTrailingComma: true,
        disallowComments: false
    });
    if (errors.length > 0) {
        for (const error of errors.slice(0, 3)) {
            findings.push(makeFinding("AEGIS011", locationAt(file.relativePath, content, error.offset), `JSON 解析错误：${printParseErrorCode(error.error)}。`));
        }
        return;
    }
    analyzeObject(file, content, data, findings);
}
function analyzeSkillMetadata(file, content, findings) {
    const normalized = content.replace(/^\uFEFF/, "");
    const frontmatter = normalized.match(/^---\s*\n([\s\S]*?)\n---(?:\s*\n|$)/);
    if (frontmatter === null) {
        findings.push(makeFinding("AEGIS009", { file: file.relativePath, line: 1, column: 1 }, "SKILL.md 缺少 YAML frontmatter；必需字段为 name 和 description。"));
        return;
    }
    const metadata = frontmatter[1] ?? "";
    const missing = [];
    if (!/^name\s*:\s*\S.*$/im.test(metadata)) {
        missing.push("name");
    }
    if (!/^description\s*:\s*\S.*$/im.test(metadata)) {
        missing.push("description");
    }
    if (missing.length > 0) {
        findings.push(makeFinding("AEGIS009", { file: file.relativePath, line: 1, column: 1 }, `SKILL.md frontmatter 缺少字段：${missing.join(", ")}。`));
    }
}
export function analyzeFile(file, content) {
    const findings = [];
    if ((file.mode & 0o002) !== 0) {
        findings.push(makeFinding("AEGIS010", { file: file.relativePath, line: 1, column: 1 }, "此安全敏感文件可被任意本地用户写入。"));
    }
    analyzeSecrets(file, content, findings);
    analyzeTextRules(file, content, findings);
    if (file.kind === "mcp-config") {
        analyzeMcpConfig(file, content, findings);
    }
    else {
        analyzeSkillMetadata(file, content, findings);
    }
    const unique = new Map();
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
//# sourceMappingURL=analyzer.js.map