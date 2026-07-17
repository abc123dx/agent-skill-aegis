import { type FailThreshold, type ScanOptions, type ScanResult } from "./types.js";
export declare const VERSION = "0.1.0";
export declare function scanProject(root?: string, options?: ScanOptions): Promise<ScanResult>;
export declare function shouldFail(result: ScanResult, threshold: FailThreshold): boolean;
export declare function isFailThreshold(value: string): value is FailThreshold;
//# sourceMappingURL=scanner.d.ts.map