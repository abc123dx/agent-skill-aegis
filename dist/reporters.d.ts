import type { OutputFormat, ScanResult } from "./types.js";
export declare function renderTerminal(result: ScanResult, options?: {
    color?: boolean;
}): string;
export declare function renderHtml(result: ScanResult): string;
export declare function renderSarif(result: ScanResult): string;
export declare function renderReport(result: ScanResult, format: OutputFormat, options?: {
    color?: boolean;
}): string;
export declare function isOutputFormat(value: string): value is OutputFormat;
//# sourceMappingURL=reporters.d.ts.map