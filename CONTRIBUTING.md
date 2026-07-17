# 参与贡献

感谢你帮助提升 Agent 工具链的安全性。我们尤其欢迎威胁模型清晰、范围小
且易于解释的规则。

## 本地开发

```bash
git clone https://github.com/abc123dx/agent-skill-aegis.git
cd agent-skill-aegis
npm ci
npm run check
```

需要 Node.js 20 或更高版本。

## 提议新规则

每条检测规则都必须：

1. 使用稳定的 `AEGIS###` 标识符；
2. 仅依据确定性的文件内容或元数据；
3. 不访问网络，也不执行扫描到的配置；
4. 同时包含不安全的正例与安全的反例；
5. 对证据中的凭据做脱敏处理；
6. 用清晰语言说明风险；
7. 提供具体且遵循最小权限原则的修复建议。

误报本身也是安全缺陷。请优先选择范围明确、可解释的信号，而不是宽泛的
关键词列表。

## Pull Request

请保持变更聚焦，并说明对 CLI、JSON schema、规则 ID 或 SARIF 输出的
兼容性影响。提交前运行 `npm run check`。

绝不要提交真实密钥或用户隐私数据。高风险示例只使用保留域名与合成凭据。

提交贡献即表示你同意使用 MIT License 授权该贡献。
