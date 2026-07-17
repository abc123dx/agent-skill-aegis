import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { discoverFiles } from "../src/discovery.js";

const temporaryDirectories: string[] = [];

async function workspace(): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), "aegis-discovery-"));
  temporaryDirectories.push(root);
  return root;
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true })
    )
  );
});

describe("discoverFiles 文件发现", () => {
  it("发现根目录与嵌套的 MCP 配置及 Agent Skill", async () => {
    const root = await workspace();
    await mkdir(path.join(root, ".cursor"), { recursive: true });
    await mkdir(path.join(root, ".agents", "skills", "reader"), {
      recursive: true
    });
    await writeFile(path.join(root, ".mcp.json"), "{}");
    await writeFile(path.join(root, ".cursor", "mcp.json"), "{}");
    await writeFile(
      path.join(root, ".agents", "skills", "reader", "SKILL.md"),
      "# Reader"
    );

    const files = await discoverFiles(root);

    expect(files.map((file) => file.relativePath)).toEqual([
      ".agents/skills/reader/SKILL.md",
      ".cursor/mcp.json",
      ".mcp.json"
    ]);
    expect(files.map((file) => file.kind)).toEqual([
      "skill",
      "mcp-config",
      "mcp-config"
    ]);
  });

  it("支持 Codex TOML 与 OpenCode 配置文件名", async () => {
    const root = await workspace();
    await mkdir(path.join(root, ".codex"), { recursive: true });
    await writeFile(path.join(root, ".codex", "config.toml"), "[mcp_servers]");
    await writeFile(path.join(root, "opencode.jsonc"), "{}");

    const files = await discoverFiles(root);

    expect(files.map((file) => file.relativePath)).toEqual([
      ".codex/config.toml",
      "opencode.jsonc"
    ]);
  });

  it("忽略生成目录与依赖目录", async () => {
    const root = await workspace();
    await mkdir(path.join(root, "node_modules", "unsafe"), {
      recursive: true
    });
    await mkdir(path.join(root, "dist"), { recursive: true });
    await writeFile(path.join(root, "node_modules", "unsafe", "SKILL.md"), "");
    await writeFile(path.join(root, "dist", ".mcp.json"), "{}");

    await expect(discoverFiles(root)).resolves.toEqual([]);
  });

  it("不遍历符号链接", async () => {
    const root = await workspace();
    await mkdir(path.join(root, "real"), { recursive: true });
    await writeFile(path.join(root, "real", "SKILL.md"), "# real");
    const { symlink } = await import("node:fs/promises");
    await symlink(path.join(root, "real"), path.join(root, "linked"));

    const files = await discoverFiles(root);

    expect(files.map((file) => file.relativePath)).toEqual(["real/SKILL.md"]);
  });
});
