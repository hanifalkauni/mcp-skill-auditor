---
name: mcp-skill-auditor
description: Security scanner and auditor for Model Context Protocol (MCP) servers, mcp_config.json, and agent skills. Detects plaintext secrets, network exfiltration, prompt injection, and supply-chain risks.
---

# MCP & Skill Security Auditor

Use this skill when the user asks to:
- Audit or scan installed MCP servers or configurations (`mcp_config.json`)
- Check for potential data leaks or secret exposure (PATs, API keys, passwords)
- Scan skill prompts (`SKILL.md`) for prompt injection, hidden instructions, or markdown exfiltration tunnels
- Review local MCP server code for unexpected outbound network connections (HTTP, WebSockets, sockets)

## Architecture

This skill operates on a **hybrid model**:
1. **Engine (Deterministic Go CLI)**: Runs locally outside LLM context to prevent prompt injection manipulation.
2. **Analysis & Remediation (Agent Skill)**: Parses scanner findings, filters context, and provides concrete remediation code diffs to the user.

## How to Run the Scanner

Run the `auditor.exe` (or `mcp-skill-auditor` binary):

### 1. Full Audit (Auto-detects mcp_config.json and installed skills)
```powershell
.\auditor.exe
```

### 2. Generate Markdown Report
```powershell
.\auditor.exe -format markdown -out audit_report.md
```

### 3. Scan a Specific Local MCP Server Codebase
```powershell
.\auditor.exe -target "./my-mcp-server"
```

### 4. CI / Fail-On Mode (Returns exit code 1 on HIGH or CRITICAL issues)
```powershell
.\auditor.exe -fail-on HIGH
```

## Interpreting Findings

When presenting findings to the user:
1. **Critical (CRITICAL)**: Hardcoded secrets in `mcp_config.json` (`CFG-001`), markdown image exfiltration tunnels (`SKL-002`), or cloud metadata SSRF probing (`SRC-SSRF`). Immediate action required.
2. **High (HIGH)**: Direct shell execution (`CFG-004`), insecure HTTP endpoints (`CFG-006`), prompt injection keywords (`SKL-004`), zero-width steganography (`SKL-001`), system role/delimiter spoofing (`SKL-006`), destructive directives (`SKL-008`, `SRC-DEST`), or path traversal (`SRC-TRAV`).
3. **Medium (MEDIUM)**: Unpinned dependencies (`@latest`), unscoped public npm packages (`CFG-007`), hidden HTML elements (`SKL-007`), bulk environment variable dumps (`os.environ`), or direct access to `.env` files (`SKL-005`, `SRC-SENS-FILE`).
4. **Low / Info (LOW/INFO)**: Standard verified HTTP client usages in MCP tools that have legitimate network features.

Always prioritize remediation:
- Suggest moving plaintext secrets into environment variables or using the [Samar MCP Server](https://github.com/hanifalkauni/samar-mcp) privacy middleware.
- Suggest pinning `@latest` versions to immutable git commit hashes or release tags.
- Propose concrete code diffs to patch identified vulnerabilities.
