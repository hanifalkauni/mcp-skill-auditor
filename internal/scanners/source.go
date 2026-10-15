package scanners

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"mcp-skill-auditor/internal/model"
)

type sourceRule struct {
	RuleID         string
	Title          string
	Description    string
	Severity       model.Severity
	Category       model.Category
	Pattern        *regexp.Regexp
	Extensions     []string
	Recommendation string
}

var sourceRules = []sourceRule{
	// Network Calls in JS/TS
	{
		RuleID:         "SRC-NET-JS",
		Title:          "Outbound HTTP/Network Request in JavaScript/TypeScript",
		Description:    "Code performs outgoing network calls (fetch, axios, http.request) which can exfiltrate local data.",
		Severity:       model.SeverityMedium,
		Category:       model.CatNetworkEgress,
		Pattern:        regexp.MustCompile(`\b(fetch\s*\(|axios\.(get|post|put|delete|request)|http\.request|https\.request|new\s+WebSocket\s*\(|got\s*\()`),
		Extensions:     []string{".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"},
		Recommendation: "Ensure network destinations are verified against an allowlist and do not transmit credentials or local file data.",
	},
	// Network Calls in Python
	{
		RuleID:         "SRC-NET-PY",
		Title:          "Outbound HTTP/Network Request in Python",
		Description:    "Python code makes external HTTP or socket connections (requests, urllib, httpx).",
		Severity:       model.SeverityMedium,
		Category:       model.CatNetworkEgress,
		Pattern:        regexp.MustCompile(`\b(requests\.(get|post|put|delete|request)|urllib\.request|httpx\.(get|post|Client)|aiohttp\.ClientSession|socket\.socket)`),
		Extensions:     []string{".py"},
		Recommendation: "Verify external endpoints and ensure no sensitive context/variables are sent across unvetted connections.",
	},
	// Network Calls in Go
	{
		RuleID:         "SRC-NET-GO",
		Title:          "Outbound HTTP/Socket Connection in Go",
		Description:    "Go code initiates outbound network traffic using net/http or net.Dial.",
		Severity:       model.SeverityLow,
		Category:       model.CatNetworkEgress,
		Pattern:        regexp.MustCompile(`\b(http\.Get|http\.Post|http\.NewRequest|http\.DefaultClient|net\.Dial)\b`),
		Extensions:     []string{".go"},
		Recommendation: "Confirm outbound network endpoints are strictly necessary for the MCP tool's stated purpose.",
	},
	// Network Calls in Shell / PowerShell
	{
		RuleID:         "SRC-NET-SH",
		Title:          "Outbound Network Transfer in Shell/PowerShell Script",
		Description:    "Script invokes curl, wget, Invoke-WebRequest, or Invoke-RestMethod.",
		Severity:       model.SeverityHigh,
		Category:       model.CatNetworkEgress,
		Pattern:        regexp.MustCompile(`(?i)\b(curl\s+|wget\s+|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer)`),
		Extensions:     []string{".sh", ".bash", ".ps1", ".bat", ".cmd"},
		Recommendation: "Audit script network endpoints. Prefer standard MCP stdio protocol over standalone curl/wget web requests.",
	},
	// Environment Bulk Harvesting
	{
		RuleID:         "SRC-ENV-DUMP",
		Title:          "Potential Environment Variable Bulk Harvesting",
		Description:    "Script clones or iterates over the entire process environment table, which can expose all machine secrets.",
		Severity:       model.SeverityMedium,
		Category:       model.CatSecretLeak,
		Pattern:        regexp.MustCompile(`(?:\b(?:os\.Environ\(\)|Get-ChildItem\s+env:)\b|\b(?:dict\s*\(\s*os\.environ|\{\s*\.\.\.process\.env|\{\s*\*\*os\.environ|env:\s*process\.env|os\.environ\.copy\(\)|os\.environ\.items\(\)|Object\.entries\s*\(\s*process\.env|Object\.keys\s*\(\s*process\.env)\b)`),
		Extensions:     []string{".py", ".js", ".ts", ".go", ".ps1"},
		Recommendation: "Only read specific, explicitly required environment variables. Avoid cloning or dumping the entire environment table.",
	},
	// Sensitive Files Direct Read
	{
		RuleID:         "SRC-SENS-FILE",
		Title:          "Direct Access to Sensitive File (.env, SSH keys)",
		Description:    "Code attempts to directly open or read confidential files like .env or private keys.",
		Severity:       model.SeverityHigh,
		Category:       model.CatSensitiveFileRead,
		Pattern:        regexp.MustCompile(`(?i)["'][^"']*(\.env(\.[a-z0-9]+)?["']|id_rsa|id_ed25519|\.aws/credentials)`),
		Extensions:     []string{".py", ".js", ".ts", ".go", ".sh", ".ps1"},
		Recommendation: "Avoid hardcoding access to sensitive files. Use a dedicated masking vault like Samar.",
	},
	// Dynamic Code Evaluation
	{
		RuleID:         "SRC-EVAL",
		Title:          "Dynamic Code Execution (eval / exec)",
		Description:    "Use of eval() or exec() allows arbitrary code execution if user or LLM input reaches it.",
		Severity:       model.SeverityHigh,
		Category:       model.CatSuspiciousCommand,
		Pattern:        regexp.MustCompile(`(?:^|[^\.])\b(eval\s*\(|exec\s*\(|new\s+Function\s*\(|child_process\.(?:exec|execSync))`),
		Extensions:     []string{".py", ".js", ".ts"},
		Recommendation: "Avoid dynamic eval/exec functions to prevent arbitrary remote code execution.",
	},
	// SSRF & Cloud Metadata Probing
	{
		RuleID:         "SRC-SSRF",
		Title:          "Potential SSRF: Cloud Metadata or Intranet IP Probing",
		Description:    "Code initiates requests to cloud metadata (169.254.169.254) or intranet IP ranges, risking IAM role theft.",
		Severity:       model.SeverityCritical,
		Category:       model.CatSSRF,
		Pattern:        regexp.MustCompile(`(?i)(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|\b(?:fetch|requests\.(?:get|post)|axios|http\.Get|net\.Dial)\s*\(\s*["']https?://(?:127\.0\.0\.1|localhost|10\.\d{1,3}|192\.168\.|172\.(?:1[6-9]|2\d|3[01]))\b)`),
		Extensions:     []string{".py", ".js", ".ts", ".go", ".sh", ".ps1"},
		Recommendation: "Block internal network ranges and cloud instance metadata IP addresses from tool requests via egress allowlists.",
	},
	// Path Traversal / Boundary Escaping
	{
		RuleID:         "SRC-TRAV",
		Title:          "Path Traversal Pattern Detected (../..)",
		Description:    "File operations contain directory traversal sequences (../..) which can escape workspace roots if not strictly bounded.",
		Severity:       model.SeverityHigh,
		Category:       model.CatPathTraversal,
		Pattern:        regexp.MustCompile(`(?i)(?:open|readFile|readFileSync|createReadStream|join|resolve)\s*\([^)]*(\.\./\.\.|\.\.\\\.\.)`),
		Extensions:     []string{".py", ".js", ".ts", ".go"},
		Recommendation: "Sanitize paths using filepath.Clean/path.resolve and assert that the target path starts with the workspace root directory.",
	},
	// Destructive Operations
	{
		RuleID:         "SRC-DEST",
		Title:          "Destructive Filesystem or Database Operation",
		Description:    "Script executes destructive recursive delete or drop operations.",
		Severity:       model.SeverityHigh,
		Category:       model.CatExcessiveAgency,
		Pattern:        regexp.MustCompile(`(?i)\b(shutil\.rmtree\s*\(|fs\.rmSync\s*\(|fs\.rmdirSync\s*\(|rmdir\s+/[sq]|rm\s+-rf|drop\s+database|drop\s+table)\b`),
		Extensions:     []string{".py", ".js", ".ts", ".go", ".sh", ".ps1"},
		Recommendation: "Require human confirmation (elicit prompt) before performing irreversible deletion or drops.",
	},
}

// ScanSourceFile scans source code files for dangerous operations and exfiltration logic.
func ScanSourceFile(filePath string) ([]model.Finding, error) {
	ext := strings.ToLower(filepath.Ext(filePath))
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open source file %s: %w", filePath, err)
	}
	defer file.Close()

	var findings []model.Finding
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip comments
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		for _, rule := range sourceRules {
			if !matchesExt(ext, rule.Extensions) {
				continue
			}

			if rule.Pattern.MatchString(line) {
				findings = append(findings, model.Finding{
					ID:             fmt.Sprintf("%s-%d", rule.RuleID, lineNum),
					RuleID:         rule.RuleID,
					Title:          rule.Title,
					Description:    rule.Description,
					Severity:       rule.Severity,
					Category:       rule.Category,
					File:           filePath,
					Line:           lineNum,
					Snippet:        sanitizeSnippet(trimmed),
					Recommendation: rule.Recommendation,
				})
			}
		}
	}

	return findings, scanner.Err()
}

func matchesExt(targetExt string, allowed []string) bool {
	for _, a := range allowed {
		if strings.EqualFold(targetExt, a) {
			return true
		}
	}
	return false
}
