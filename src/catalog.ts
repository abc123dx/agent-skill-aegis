import type { Finding, Severity } from "./types.js";

export interface RuleDefinition {
  id: string;
  title: string;
  severity: Severity;
  category: Finding["category"];
  description: string;
  recommendation: string;
}

export const rules = {
  AEGIS001: {
    id: "AEGIS001",
    title: "硬编码凭据",
    severity: "critical",
    category: "credentials",
    description: "扫描文件中直接存储了疑似凭据的值。",
    recommendation:
      "从版本控制中移除该值并立即轮换，改用环境变量或密钥管理器引用。"
  },
  AEGIS002: {
    id: "AEGIS002",
    title: "可执行依赖未锁定版本",
    severity: "high",
    category: "dependency",
    description: "npx 或 uvx 每次运行时可能解析到不同的软件包版本。",
    recommendation:
      "锁定精确的软件包版本（例如 package@1.2.3 或 package==1.2.3），并审查锁文件或来源证明。"
  },
  AEGIS003: {
    id: "AEGIS003",
    title: "下载内容被直接执行",
    severity: "critical",
    category: "execution",
    description: "远程内容通过管道或参数直接交给了解释器。",
    recommendation:
      "先下载到文件，验证摘要或签名并完成审查，仅执行确认可信的制品。"
  },
  AEGIS004: {
    id: "AEGIS004",
    title: "危险的 Shell 执行",
    severity: "high",
    category: "execution",
    description: "Shell 命令可能执行范围过大或难以审查的操作。",
    recommendation:
      "使用范围明确的可执行文件与参数列表，移除递归删除、宽松 chmod 和 Shell 间接执行。"
  },
  AEGIS005: {
    id: "AEGIS005",
    title: "文件系统访问范围过宽",
    severity: "high",
    category: "permissions",
    description: "服务器或技能可能访问文件系统根目录或完整的用户主目录。",
    recommendation:
      "仅授予工具必需的最小项目级读写目录权限。"
  },
  AEGIS006: {
    id: "AEGIS006",
    title: "不安全的远程传输",
    severity: "medium",
    category: "transport",
    description: "非本地端点使用了明文 HTTP。",
    recommendation:
      "使用启用证书验证的 HTTPS；若端点仅供本机使用，则绑定到回环地址。"
  },
  AEGIS007: {
    id: "AEGIS007",
    title: "提示词注入指令",
    severity: "high",
    category: "prompt-safety",
    description: "指令文本试图覆盖更高优先级或先前的指令。",
    recommendation:
      "移除操纵指令优先级的内容，并明确限定技能获准执行的行为。"
  },
  AEGIS008: {
    id: "AEGIS008",
    title: "潜在的数据外传指令",
    severity: "critical",
    category: "prompt-safety",
    description: "指令文本要求秘密披露或传输敏感数据。",
    recommendation:
      "移除隐蔽传输行为，并要求明确的用户批准、目标白名单和数据最小化。"
  },
  AEGIS009: {
    id: "AEGIS009",
    title: "缺少 Agent Skill 元数据",
    severity: "medium",
    category: "metadata",
    description: "SKILL.md 缺少必需的 frontmatter 或标识字段。",
    recommendation:
      "添加 YAML frontmatter，提供稳定的 name 和准确说明技能用途与边界的 description。"
  },
  AEGIS010: {
    id: "AEGIS010",
    title: "安全文件可被任意用户写入",
    severity: "medium",
    category: "permissions",
    description: "扫描到的配置或技能可被任意本地用户修改。",
    recommendation:
      "移除其他用户写权限（例如 chmod o-w），并核验文件所有权。"
  },
  AEGIS011: {
    id: "AEGIS011",
    title: "无效的 MCP 配置",
    severity: "high",
    category: "parsing",
    description: "MCP JSON 或 JSONC 配置无法解析。",
    recommendation:
      "先修复报告中的 JSON 语法错误，再将配置加载到 Agent 宿主。"
  },
  AEGIS012: {
    id: "AEGIS012",
    title: "隐瞒行为指令",
    severity: "high",
    category: "prompt-safety",
    description: "指令文本要求 Agent 向用户隐瞒某项操作。",
    recommendation:
      "公开所有具有实质影响的行为，并要求用户在充分知情后批准。"
  }
} as const satisfies Record<string, RuleDefinition>;

export type RuleId = keyof typeof rules;

export function makeFinding(
  id: RuleId,
  location: Pick<Finding, "file" | "line" | "column">,
  message: string,
  evidence?: string
): Finding {
  const rule = rules[id];
  return {
    ...location,
    ruleId: rule.id,
    title: rule.title,
    severity: rule.severity,
    category: rule.category,
    message,
    recommendation: rule.recommendation,
    ...(evidence === undefined ? {} : { evidence })
  };
}
