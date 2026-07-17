# Contributing

Thank you for helping make agent tooling safer. Small, explainable rules with a
clear threat model are especially welcome.

## Local development

```bash
git clone https://github.com/abc123dx/agent-skill-aegis.git
cd agent-skill-aegis
npm install
npm run check
```

Node.js 20 or newer is required.

## Proposing a rule

Every detection rule must:

1. use a stable `AEGIS###` identifier;
2. derive from deterministic file content or metadata;
3. avoid network calls and executing scanned configuration;
4. include an unsafe positive fixture and a safe negative fixture;
5. redact credentials in evidence;
6. explain the risk in plain language; and
7. include a concrete, least-privilege remediation.

False positives are security defects. Prefer a narrow, explainable signal over
a broad keyword list.

## Pull requests

Keep changes focused and describe any compatibility impact to the CLI, JSON
schema, rule IDs, or SARIF output. Run `npm run check` before submitting.

Never commit real secrets or private user data. The vulnerable example uses
reserved domains and synthetic credentials intentionally.

By contributing, you agree that your contribution is licensed under the MIT
License.
