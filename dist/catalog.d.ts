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
        readonly title: "硬编码凭据";
        readonly severity: "critical";
        readonly category: "credentials";
        readonly description: "扫描文件中直接存储了疑似凭据的值。";
        readonly recommendation: "从版本控制中移除该值并立即轮换，改用环境变量或密钥管理器引用。";
    };
    readonly AEGIS002: {
        readonly id: "AEGIS002";
        readonly title: "可执行依赖未锁定版本";
        readonly severity: "high";
        readonly category: "dependency";
        readonly description: "npx 或 uvx 每次运行时可能解析到不同的软件包版本。";
        readonly recommendation: "锁定精确的软件包版本（例如 package@1.2.3 或 package==1.2.3），并审查锁文件或来源证明。";
    };
    readonly AEGIS003: {
        readonly id: "AEGIS003";
        readonly title: "下载内容被直接执行";
        readonly severity: "critical";
        readonly category: "execution";
        readonly description: "远程内容通过管道或参数直接交给了解释器。";
        readonly recommendation: "先下载到文件，验证摘要或签名并完成审查，仅执行确认可信的制品。";
    };
    readonly AEGIS004: {
        readonly id: "AEGIS004";
        readonly title: "危险的 Shell 执行";
        readonly severity: "high";
        readonly category: "execution";
        readonly description: "Shell 命令可能执行范围过大或难以审查的操作。";
        readonly recommendation: "使用范围明确的可执行文件与参数列表，移除递归删除、宽松 chmod 和 Shell 间接执行。";
    };
    readonly AEGIS005: {
        readonly id: "AEGIS005";
        readonly title: "文件系统访问范围过宽";
        readonly severity: "high";
        readonly category: "permissions";
        readonly description: "服务器或技能可能访问文件系统根目录或完整的用户主目录。";
        readonly recommendation: "仅授予工具必需的最小项目级读写目录权限。";
    };
    readonly AEGIS006: {
        readonly id: "AEGIS006";
        readonly title: "不安全的远程传输";
        readonly severity: "medium";
        readonly category: "transport";
        readonly description: "非本地端点使用了明文 HTTP。";
        readonly recommendation: "使用启用证书验证的 HTTPS；若端点仅供本机使用，则绑定到回环地址。";
    };
    readonly AEGIS007: {
        readonly id: "AEGIS007";
        readonly title: "提示词注入指令";
        readonly severity: "high";
        readonly category: "prompt-safety";
        readonly description: "指令文本试图覆盖更高优先级或先前的指令。";
        readonly recommendation: "移除操纵指令优先级的内容，并明确限定技能获准执行的行为。";
    };
    readonly AEGIS008: {
        readonly id: "AEGIS008";
        readonly title: "潜在的数据外传指令";
        readonly severity: "critical";
        readonly category: "prompt-safety";
        readonly description: "指令文本要求秘密披露或传输敏感数据。";
        readonly recommendation: "移除隐蔽传输行为，并要求明确的用户批准、目标白名单和数据最小化。";
    };
    readonly AEGIS009: {
        readonly id: "AEGIS009";
        readonly title: "缺少 Agent Skill 元数据";
        readonly severity: "medium";
        readonly category: "metadata";
        readonly description: "SKILL.md 缺少必需的 frontmatter 或标识字段。";
        readonly recommendation: "添加 YAML frontmatter，提供稳定的 name 和准确说明技能用途与边界的 description。";
    };
    readonly AEGIS010: {
        readonly id: "AEGIS010";
        readonly title: "安全文件可被任意用户写入";
        readonly severity: "medium";
        readonly category: "permissions";
        readonly description: "扫描到的配置或技能可被任意本地用户修改。";
        readonly recommendation: "移除其他用户写权限（例如 chmod o-w），并核验文件所有权。";
    };
    readonly AEGIS011: {
        readonly id: "AEGIS011";
        readonly title: "无效的 MCP 配置";
        readonly severity: "high";
        readonly category: "parsing";
        readonly description: "MCP JSON 或 JSONC 配置无法解析。";
        readonly recommendation: "先修复报告中的 JSON 语法错误，再将配置加载到 Agent 宿主。";
    };
    readonly AEGIS012: {
        readonly id: "AEGIS012";
        readonly title: "隐瞒行为指令";
        readonly severity: "high";
        readonly category: "prompt-safety";
        readonly description: "指令文本要求 Agent 向用户隐瞒某项操作。";
        readonly recommendation: "公开所有具有实质影响的行为，并要求用户在充分知情后批准。";
    };
};
export type RuleId = keyof typeof rules;
export declare function makeFinding(id: RuleId, location: Pick<Finding, "file" | "line" | "column">, message: string, evidence?: string): Finding;
//# sourceMappingURL=catalog.d.ts.map