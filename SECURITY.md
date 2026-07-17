# Security policy

Agent Skill Aegis processes security-sensitive configuration. Please do not
paste live credentials, private prompts, or unredacted scan output into a
public issue.

## Supported versions

Security fixes are provided for the latest release on the `main` branch. Until
the project reaches 1.0, minor releases may include schema or rule refinements
documented in the changelog.

## Report a vulnerability

Use
[GitHub's private vulnerability reporting](https://github.com/abc123dx/agent-skill-aegis/security/advisories/new)
and include:

- the affected version and environment;
- a minimal, synthetic reproduction;
- the expected security boundary;
- the potential impact; and
- any suggested mitigation.

You should receive an acknowledgement within 72 hours. We aim to provide an
initial assessment within seven days and coordinate disclosure after a fix is
available.

## Scanner safety

Aegis performs read-only local analysis. It does not execute MCP commands,
install scanned packages, follow symbolic links, or send file contents over
the network. Reports redact credential evidence, but JSON and HTML reports may
still contain file paths and matched instruction text. Treat reports as
sensitive artifacts.

This tool is a focused static analyzer, not a guarantee that an MCP server or
Agent Skill is safe. Review package provenance, runtime behavior, permissions,
and network policy before granting an agent access to valuable data.
