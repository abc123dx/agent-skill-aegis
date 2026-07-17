#!/usr/bin/env node
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { Command, InvalidArgumentError } from "commander";
import { isOutputFormat, renderReport } from "./reporters.js";
import { isFailThreshold, scanProject, shouldFail, VERSION } from "./scanner.js";
function outputFormat(value) {
    if (!isOutputFormat(value)) {
        throw new InvalidArgumentError("Expected terminal, json, html, or sarif.");
    }
    return value;
}
function failThreshold(value) {
    if (!isFailThreshold(value)) {
        throw new InvalidArgumentError("Expected critical, high, medium, low, info, or never.");
    }
    return value;
}
function positiveInteger(value) {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isSafeInteger(parsed) || parsed <= 0) {
        throw new InvalidArgumentError("Expected a positive integer.");
    }
    return parsed;
}
const program = new Command();
program
    .name("agent-skill-aegis")
    .description("Deterministic supply-chain security scanner for MCP configs and Agent Skills.")
    .version(VERSION);
program
    .command("scan")
    .description("scan a directory for security-sensitive agent configuration")
    .argument("[path]", "directory to scan", ".")
    .option("-f, --format <format>", "terminal, json, html, or sarif", outputFormat, "terminal")
    .option("-o, --output <file>", "write the report to a file")
    .option("--fail-on <severity>", "exit 1 at or above this severity, or never", failThreshold, "high")
    .option("--max-file-size <bytes>", "skip candidate files larger than this", positiveInteger, 1024 * 1024)
    .option("--no-color", "disable ANSI colors")
    .option("-q, --quiet", "suppress stdout when --output is used", false)
    .action(async (scanPath, options) => {
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
                process.stdout.write(`Aegis wrote ${options.format} report to ${outputPath}\n`);
            }
        }
        else {
            process.stdout.write(report);
            if (!report.endsWith("\n")) {
                process.stdout.write("\n");
            }
        }
        if (shouldFail(result, options.failOn)) {
            process.exitCode = 1;
        }
    }
    catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        process.stderr.write(`agent-skill-aegis: ${message}\n`);
        process.exitCode = 2;
    }
});
await program.parseAsync(process.argv);
//# sourceMappingURL=cli.js.map