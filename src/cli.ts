#!/usr/bin/env node

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { Command, InvalidArgumentError } from "commander";
import { isOutputFormat, renderReport } from "./reporters.js";
import {
  isFailThreshold,
  scanProject,
  shouldFail,
  VERSION
} from "./scanner.js";
import type {
  FailThreshold,
  OutputFormat
} from "./types.js";

function outputFormat(value: string): OutputFormat {
  if (!isOutputFormat(value)) {
    throw new InvalidArgumentError(
      "应为 terminal、json、html 或 sarif。"
    );
  }
  return value;
}

function failThreshold(value: string): FailThreshold {
  if (!isFailThreshold(value)) {
    throw new InvalidArgumentError(
      "应为 critical、high、medium、low、info 或 never。"
    );
  }
  return value;
}

function positiveInteger(value: string): number {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new InvalidArgumentError("应为正整数。");
  }
  return parsed;
}

interface CliOptions {
  color: boolean;
  failOn: FailThreshold;
  format: OutputFormat;
  maxFileSize: number;
  output?: string;
  quiet: boolean;
}

const program = new Command();

const helpTitles: Record<string, string> = {
  "Usage:": "用法：",
  "Arguments:": "参数：",
  "Options:": "选项：",
  "Global Options:": "全局选项：",
  "Commands:": "命令："
};

function configureChineseHelp(command: Command): Command {
  return command
    .helpOption("-h, --help", "显示帮助")
    .configureHelp({
      styleTitle: (title) => helpTitles[title] ?? title,
      optionDescription: (option) => option.description,
      argumentDescription: (argument) => argument.description
    })
    .configureOutput({
      outputError: (message, write) => {
        const localized = message
          .replace(/^error:/, "错误：")
          .replace(/unknown command '([^']+)'/g, "未知命令“$1”")
          .replace(/unknown option '([^']+)'/g, "未知选项“$1”")
          .replace(
            /option '([^']+)' argument '([^']+)' is invalid\.\s*/g,
            "选项“$1”的参数“$2”无效。"
          )
          .replace(
            /option '([^']+)' argument missing/g,
            "选项“$1”缺少参数"
          )
          .replace(
            /missing required argument '([^']+)'/g,
            "缺少必需参数“$1”"
          )
          .replace(/too many arguments/g, "参数过多")
          .replace(/Did you mean ([^?]+)\?/g, "你是否想输入 $1？");
        write(localized);
      }
    });
}

configureChineseHelp(program)
  .name("agent-skill-aegis")
  .description(
    "面向 MCP 配置与 Agent Skill 的确定性供应链安全扫描器。"
  )
  .version(VERSION, "-V, --version", "显示版本号")
  .addHelpCommand("help [command]", "显示指定命令的帮助");

const scanCommand = program
  .command("scan")
  .description("扫描目录中的安全敏感 Agent 配置")
  .argument("[path]", "要扫描的目录", ".")
  .option(
    "-f, --format <format>",
    "报告格式：terminal、json、html 或 sarif",
    outputFormat,
    "terminal"
  )
  .option("-o, --output <file>", "将报告写入文件")
  .option(
    "--fail-on <severity>",
    "达到此严重级别时以 1 退出，never 表示永不拦截",
    failThreshold,
    "high"
  )
  .option(
    "--max-file-size <bytes>",
    "跳过大于此字节数的候选文件",
    positiveInteger,
    1024 * 1024
  )
  .option("--no-color", "禁用 ANSI 颜色")
  .option("-q, --quiet", "使用 --output 时不输出到标准输出", false);

configureChineseHelp(scanCommand)
  .action(async (scanPath: string, options: CliOptions) => {
    try {
      const result = await scanProject(scanPath, {
        maxFileSize: options.maxFileSize
      });
      const report = renderReport(result, options.format, {
        color: options.color && process.stdout.isTTY
      });

      if (options.output !== undefined) {
        const outputPath = path.resolve(options.output);
        await mkdir(path.dirname(outputPath), { recursive: true });
        await writeFile(outputPath, report, "utf8");
        if (!options.quiet) {
          process.stdout.write(
            `Aegis 已将 ${options.format} 报告写入 ${outputPath}\n`
          );
        }
      } else {
        process.stdout.write(report);
        if (!report.endsWith("\n")) {
          process.stdout.write("\n");
        }
      }

      if (shouldFail(result, options.failOn)) {
        process.exitCode = 1;
      }
    } catch (error) {
      const errorCode = (error as NodeJS.ErrnoException).code;
      const message =
        errorCode === "ENOENT"
          ? `找不到要扫描的路径：${path.resolve(scanPath)}`
          : errorCode === "EACCES"
            ? `无权访问要扫描的路径：${path.resolve(scanPath)}`
            : errorCode === "ENOTDIR"
              ? `扫描路径不是目录：${path.resolve(scanPath)}`
              : error instanceof Error
                ? error.message
                : String(error);
      process.stderr.write(`agent-skill-aegis：${message}\n`);
      process.exitCode = 2;
    }
  });

await program.parseAsync(process.argv);
