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

describe("discoverFiles", () => {
  it("discovers root and nested MCP configs and Agent Skills", async () => {
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

  it("supports Codex TOML and OpenCode config names", async () => {
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

  it("ignores generated and dependency directories", async () => {
    const root = await workspace();
    await mkdir(path.join(root, "node_modules", "unsafe"), {
      recursive: true
    });
    await mkdir(path.join(root, "dist"), { recursive: true });
    await writeFile(path.join(root, "node_modules", "unsafe", "SKILL.md"), "");
    await writeFile(path.join(root, "dist", ".mcp.json"), "{}");

    await expect(discoverFiles(root)).resolves.toEqual([]);
  });

  it("does not traverse symbolic links", async () => {
    const root = await workspace();
    await mkdir(path.join(root, "real"), { recursive: true });
    await writeFile(path.join(root, "real", "SKILL.md"), "# real");
    const { symlink } = await import("node:fs/promises");
    await symlink(path.join(root, "real"), path.join(root, "linked"));

    const files = await discoverFiles(root);

    expect(files.map((file) => file.relativePath)).toEqual(["real/SKILL.md"]);
  });
});
