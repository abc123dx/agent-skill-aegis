import { opendir, stat } from "node:fs/promises";
import path from "node:path";
const ignoredDirectories = new Set([
    ".git",
    ".next",
    ".turbo",
    ".venv",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "vendor"
]);
function classify(relativePath) {
    const normalized = relativePath.split(path.sep).join("/");
    const base = path.basename(normalized).toLowerCase();
    if (base === "skill.md") {
        return "skill";
    }
    const isMcpNamed = base === ".mcp.json" ||
        base === "mcp.json" ||
        base === "mcp.jsonc" ||
        base === "mcp_config.json" ||
        base.endsWith(".mcp.json") ||
        base === "claude_desktop_config.json";
    const isCodexMcpToml = base === "config.toml" &&
        normalized.toLowerCase().split("/").includes(".codex");
    const isOpenCodeConfig = base === "opencode.json" || base === "opencode.jsonc";
    if (isMcpNamed || isCodexMcpToml || isOpenCodeConfig) {
        return "mcp-config";
    }
    return undefined;
}
export async function discoverFiles(root) {
    const absoluteRoot = path.resolve(root);
    const files = [];
    async function walk(directory) {
        const entries = await opendir(directory);
        for await (const entry of entries) {
            if (entry.isSymbolicLink()) {
                continue;
            }
            if (entry.isDirectory()) {
                if (!ignoredDirectories.has(entry.name)) {
                    await walk(path.join(directory, entry.name));
                }
                continue;
            }
            if (!entry.isFile()) {
                continue;
            }
            const absolutePath = path.join(directory, entry.name);
            const relativePath = path.relative(absoluteRoot, absolutePath);
            const kind = classify(relativePath);
            if (kind === undefined) {
                continue;
            }
            const metadata = await stat(absolutePath);
            files.push({
                absolutePath,
                relativePath: relativePath.split(path.sep).join("/"),
                kind,
                mode: metadata.mode,
                size: metadata.size
            });
        }
    }
    await walk(absoluteRoot);
    return files.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
}
//# sourceMappingURL=discovery.js.map