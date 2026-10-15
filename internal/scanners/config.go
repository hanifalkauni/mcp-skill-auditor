package scanners

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"mcp-skill-auditor/internal/model"
)

// utf8BOM is the byte-order-mark that Windows editors (Notepad, some IDE
// configs, PowerShell `Set-Content -Encoding utf8`) prepend to files. A leading
// BOM makes encoding/json fail, so it must be stripped before parsing.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

type MCPServerEntry struct {
	Command  string            `json:"command"`
	Args     []string          `json:"args"`
	Env      map[string]string `json:"env"`
	Disabled bool              `json:"disabled"`
}

type MCPConfig struct {
	MCPServers map[string]MCPServerEntry `json:"mcpServers"`
}

var (
	secretKeyRegex = regexp.MustCompile(`(?i)(token|pat|secret|key|password|credential|auth|bearer|private)`)
	jwtPattern     = regexp.MustCompile(`^ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$`)
	ghPatPattern   = regexp.MustCompile(`^(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})`)
	genericTokenRe = regexp.MustCompile(`^[A-Za-z0-9_\-]{24,}$`)
)

// ScanMCPConfig scans an mcp_config.json file for security risks and data leaks.
func ScanMCPConfig(filePath string) ([]model.Finding, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("unable to read mcp config file: %w", err)
	}

	// Strip a leading UTF-8 BOM so BOM-prefixed configs (common on Windows)
	// still parse instead of silently yielding zero findings.
	data = bytes.TrimPrefix(data, utf8BOM)

	var config MCPConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("invalid json in mcp config: %w", err)
	}

	var findings []model.Finding

	for serverName, srv := range config.MCPServers {
		statusSuffix := ""
		if srv.Disabled {
			statusSuffix = " (disabled)"
		}

		// 1. Scan environment variables for hardcoded secrets
		for envKey, envVal := range srv.Env {
			trimmedVal := strings.TrimSpace(envVal)
			if trimmedVal == "" {
				continue
			}

			// Check if env key looks like a secret
			if secretKeyRegex.MatchString(envKey) {
				// Don't flag if it's clearly an env reference like ${MY_TOKEN} or %MY_TOKEN%
				if strings.HasPrefix(trimmedVal, "${") || strings.HasPrefix(trimmedVal, "$") || (strings.HasPrefix(trimmedVal, "%") && strings.HasSuffix(trimmedVal, "%")) {
					continue
				}

				// Redact snippet for display
				redacted := maskValue(trimmedVal)

				findings = append(findings, model.Finding{
					ID:             fmt.Sprintf("CFG-SEC-%s-%s", serverName, envKey),
					RuleID:         "CFG-001",
					Title:          fmt.Sprintf("Hardcoded Secret in MCP Config: %s -> %s%s", serverName, envKey, statusSuffix),
					Severity:       model.SeverityCritical,
					Category:       model.CatSecretLeak,
					File:           filePath,
					Snippet:        fmt.Sprintf(`"%s": "%s"`, envKey, redacted),
					Description:    fmt.Sprintf("Server '%s' defines a sensitive environment variable '%s' directly in plaintext inside mcp_config.json.", serverName, envKey),
					Recommendation: "Do not store plaintext tokens in mcp_config.json. Read from system environment variables, use a secret manager, or pass via Samar masking middleware.",
				})
			} else if jwtPattern.MatchString(trimmedVal) || ghPatPattern.MatchString(trimmedVal) || (len(trimmedVal) > 32 && genericTokenRe.MatchString(trimmedVal)) {
				// High-entropy value in an ordinary looking key
				findings = append(findings, model.Finding{
					ID:             fmt.Sprintf("CFG-ENT-%s-%s", serverName, envKey),
					RuleID:         "CFG-002",
					Title:          fmt.Sprintf("High-Entropy Secret Pattern in MCP Config: %s -> %s%s", serverName, envKey, statusSuffix),
					Severity:       model.SeverityHigh,
					Category:       model.CatSecretLeak,
					File:           filePath,
					Snippet:        fmt.Sprintf(`"%s": "%s"`, envKey, maskValue(trimmedVal)),
					Description:    fmt.Sprintf("Server '%s' has environment variable '%s' containing high-entropy token-like data.", serverName, envKey),
					Recommendation: "Verify whether this value is a confidential secret. If so, move it outside of plaintext config files.",
				})
			}
		}

		// 2. Scan command and arguments for supply chain and execution risks
		fullCmd := srv.Command + " " + strings.Join(srv.Args, " ")

		// Check for unpinned @latest
		if strings.Contains(fullCmd, "@latest") {
			findings = append(findings, model.Finding{
				ID:             fmt.Sprintf("CFG-LATEST-%s", serverName),
				RuleID:         "CFG-003",
				Title:          fmt.Sprintf("Unpinned Package Dependency (@latest): %s%s", serverName, statusSuffix),
				Severity:       model.SeverityMedium,
				Category:       model.CatSupplyChainRisk,
				File:           filePath,
				Snippet:        fullCmd,
				Description:    fmt.Sprintf("Server '%s' uses an unpinned '@latest' version tag in '%s'. A compromised upstream repository could automatically deliver malicious code.", serverName, fullCmd),
				Recommendation: "Pin dependencies to a specific immutable version hash or verified semantic release tag.",
			})
		}

		// Check for arbitrary shell invocation
		cmdLower := strings.ToLower(srv.Command)
		if cmdLower == "cmd" || cmdLower == "cmd.exe" || cmdLower == "powershell" || cmdLower == "powershell.exe" || cmdLower == "bash" || cmdLower == "sh" {
			findings = append(findings, model.Finding{
				ID:             fmt.Sprintf("CFG-SHELL-%s", serverName),
				RuleID:         "CFG-004",
				Title:          fmt.Sprintf("Direct Shell Command Execution in MCP Config: %s%s", serverName, statusSuffix),
				Severity:       model.SeverityHigh,
				Category:       model.CatSuspiciousCommand,
				File:           filePath,
				Snippet:        fullCmd,
				Description:    fmt.Sprintf("Server '%s' invokes a shell interpreter directly ('%s'). This increases risk of command injection.", serverName, srv.Command),
				Recommendation: "Execute dedicated binaries directly without wrapping in interactive shells whenever possible.",
			})
		}

		// Check for insecure flags
		if strings.Contains(fullCmd, "--insecure") || strings.Contains(fullCmd, "--no-sandbox") || strings.Contains(fullCmd, "--disable-web-security") {
			findings = append(findings, model.Finding{
				ID:             fmt.Sprintf("CFG-FLAG-%s", serverName),
				RuleID:         "CFG-005",
				Title:          fmt.Sprintf("Dangerous Security Flags in MCP Args: %s%s", serverName, statusSuffix),
				Severity:       model.SeverityHigh,
				Category:       model.CatSuspiciousCommand,
				File:           filePath,
				Snippet:        fullCmd,
				Description:    fmt.Sprintf("Server '%s' uses flags that explicitly weaken security or sandbox controls.", serverName),
				Recommendation: "Remove insecure flags unless strictly required in an isolated testing sandbox.",
			})
		}

		// Check for insecure plaintext HTTP protocols (excluding local dev)
		httpRegex := regexp.MustCompile(`(?i)\bhttp://[a-zA-Z0-9\.\-_:]+`)
		for k, v := range srv.Env {
			if match := httpRegex.FindString(v); match != "" {
				lower := strings.ToLower(match)
				if strings.Contains(lower, "localhost") || strings.Contains(lower, "127.0.0.1") || strings.Contains(lower, "0.0.0.0") {
					continue
				}
				findings = append(findings, model.Finding{
					ID:             fmt.Sprintf("CFG-INSECURE-PROTO-%s-%s", serverName, k),
					RuleID:         "CFG-006",
					Title:          fmt.Sprintf("Insecure Plaintext HTTP URL in MCP Config: %s%s", serverName, statusSuffix),
					Severity:       model.SeverityHigh,
					Category:       model.CatSecurityConfig,
					File:           filePath,
					Snippet:        fmt.Sprintf(`"%s": "%s"`, k, v),
					Description:    fmt.Sprintf("Server '%s' defines a remote endpoint using plaintext HTTP (%s) which is vulnerable to eavesdropping and Man-in-the-Middle (MitM) tampering.", serverName, match),
					Recommendation: "Upgrade protocol to HTTPS (TLS) to encrypt all communications in transit.",
				})
			}
		}

		// Check for unscoped anonymous NPM packages executed with npx
		if cmdLower == "npx" {
			for _, arg := range srv.Args {
				if strings.HasPrefix(arg, "-") {
					continue
				}
				// If package is not scoped (@org/pkg) and not a github reference (github:)
				if !strings.HasPrefix(arg, "@") && !strings.HasPrefix(arg, "github:") && !strings.Contains(arg, "/") && !strings.Contains(arg, "\\") {
					findings = append(findings, model.Finding{
						ID:             fmt.Sprintf("CFG-UNSCOPED-NPM-%s", serverName),
						RuleID:         "CFG-007",
						Title:          fmt.Sprintf("Unscoped Public NPM Package: %s%s", serverName, statusSuffix),
						Severity:       model.SeverityMedium,
						Category:       model.CatSupplyChainRisk,
						File:           filePath,
						Snippet:        arg,
						Description:    fmt.Sprintf("Server '%s' uses unscoped public npm package '%s'. Unscoped packages have higher risk of typosquatting and account takeover compared to official vendor namespaces.", serverName, arg),
						Recommendation: "Verify author provenance and package download integrity, or prefer vendor-scoped packages.",
					})
					break
				}
			}
		}
	}

	return findings, nil
}

func maskValue(val string) string {
	if len(val) <= 6 {
		return "******"
	}
	prefix := val[:3]
	suffix := val[len(val)-3:]
	return fmt.Sprintf("%s...%s", prefix, suffix)
}
