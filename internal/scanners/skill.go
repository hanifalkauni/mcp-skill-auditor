package scanners

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"mcp-skill-auditor/internal/model"
)

var (
	// Markdown image exfiltration pattern: ![...](https://attacker.com/leak?data=...)
	mdImageLeakRegex = regexp.MustCompile(`!\[([^\]]*)\]\((https?://[^\s\)]+)\)`)

	// Suspicious exfiltration webhook endpoints
	exfilDomainRegex = regexp.MustCompile(`(?i)(webhook\.site|requestcatcher\.com|pipedream\.net|ngrok-free\.app|burpcollaborator\.net|oastify\.com|beeceptor\.com)`)

	// Prompt injection triggers
	promptInjectionRegexes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions`),
		regexp.MustCompile(`(?i)disregard\s+(all\s+)?(previous|prior|system)\s+(instructions|prompts)`),
		regexp.MustCompile(`(?i)(bypass|disable|override)\s+(safety|guardrail|security|sandbox)`),
		regexp.MustCompile(`(?i)(exfiltrate|leak|transmit|upload)\s+.*(secret|token|password|credential|\.env|key)`),
		regexp.MustCompile(`(?i)(send|post)\s+.*(to\s+https?://)`),
	}

	// Sensitive file references in instructions.
	// The .env branch uses a negative lookahead-free guard: `.env` must NOT be
	// followed by another letter, so real filenames like `.env` / `.env.local`
	// match while `os.environ`, `process.env` (followed by nothing) and words
	// like `.environment` do not produce false positives. A trailing `.` (as in
	// `.env.local`) or non-letter boundary is required.
	sensitiveFilePattern = regexp.MustCompile(`(?i)(\.env(\.[a-z0-9]+)?\b|\.aws/credentials|\.ssh/(id_rsa|id_ed25519|known_hosts)|/etc/passwd|/etc/shadow|ntds\.dit|wallet\.dat)`)

	// Zero-width / invisible characters used to hide prompt injections
	zeroWidthRegex = regexp.MustCompile(`[\x{200B}-\x{200D}\x{FEFF}\x{200E}\x{200F}\x{00AD}]`)

	// System tag & role spoofing (token manipulation)
	systemTagRegex = regexp.MustCompile(`(?i)(<system>|</system>|\[INST\]|\[/INST\]|<<SYS>>|<\|im_start\|>|<\|im_end\|>|<\|start_header_id\|>system|<\|end_header_id\|>)`)

	// Hidden HTML / CSS steganography
	hiddenHtmlRegex = regexp.MustCompile(`(?i)(style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)[^"']*["']|<(?:div|span|p|details)\s+[^>]*hidden)`)

	// Destructive commands without safeguards
	destructiveDirectiveRegex = regexp.MustCompile(`(?i)\b(rm\s+-rf\s+[/~]|rmdir\s+/[sq]\s+[a-z]:\\|drop\s+database|format\s+[a-z]:|git\s+reset\s+--hard\s+origin)\b`)
)

// ScanSkillFile scans a single markdown file (SKILL.md or prompt) for injection and data leak risks.
func ScanSkillFile(filePath string) ([]model.Finding, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open skill file %s: %w", filePath, err)
	}
	defer file.Close()

	var findings []model.Finding
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// 1. Check for invisible characters (zero-width chars)
		if zeroWidthRegex.MatchString(line) {
			findings = append(findings, model.Finding{
				ID:             fmt.Sprintf("SKILL-ZW-%d", lineNum),
				RuleID:         "SKL-001",
				Title:          "Invisible / Zero-Width Unicode Characters Detected",
				Severity:       model.SeverityHigh,
				Category:       model.CatPromptInjection,
				File:           filePath,
				Line:           lineNum,
				Snippet:        sanitizeSnippet(line),
				Description:    "The markdown line contains hidden/zero-width characters. Attackers often use invisible unicode to hide malicious instructions from human reviewers while LLMs still parse them.",
				Recommendation: "Strip all zero-width characters and verify if any hidden instructions were embedded.",
			})
		}

		// 2. Check for markdown image exfiltration
		if matches := mdImageLeakRegex.FindAllStringSubmatch(line, -1); len(matches) > 0 {
			for _, match := range matches {
				url := match[2]
				urlLower := strings.ToLower(url)
				if strings.Contains(urlLower, "?") && (strings.Contains(urlLower, "token") || strings.Contains(urlLower, "data") || strings.Contains(urlLower, "secret") || strings.Contains(urlLower, "leak") || strings.Contains(urlLower, "env")) {
					findings = append(findings, model.Finding{
						ID:             fmt.Sprintf("SKILL-IMGLEAK-%d", lineNum),
						RuleID:         "SKL-002",
						Title:          "Potential Markdown Image Exfiltration Tunnel",
						Severity:       model.SeverityCritical,
						Category:       model.CatNetworkEgress,
						File:           filePath,
						Line:           lineNum,
						Snippet:        match[0],
						Description:    fmt.Sprintf("Markdown image tags can trigger automated HTTP GET requests when rendered in markdown viewers/chat interfaces, exfiltrating data via URL query parameters: %s", url),
						Recommendation: "Disallow dynamic URL parameters in image tags that could carry confidential environment variables or tokens.",
					})
				}
			}
		}

		// 3. Check for suspicious webhook / data collector domains
		if exfilDomainRegex.MatchString(line) {
			findings = append(findings, model.Finding{
				ID:             fmt.Sprintf("SKILL-EXFILDOM-%d", lineNum),
				RuleID:         "SKL-003",
				Title:          "Suspicious Data Collector / Tunnel Domain",
				Severity:       model.SeverityHigh,
				Category:       model.CatNetworkEgress,
				File:           filePath,
				Line:           lineNum,
				Snippet:        sanitizeSnippet(line),
				Description:    "Reference to public request-catching/tunneling service commonly used in proof-of-concept exfiltration attacks.",
				Recommendation: "Verify why this public tunneling service is referenced. Ensure it is not intended as an exfiltration sink.",
			})
		}

		// 4. Check for prompt injection keywords
		for _, re := range promptInjectionRegexes {
			if match := re.FindString(line); match != "" {
				findings = append(findings, model.Finding{
					ID:             fmt.Sprintf("SKILL-INJECT-%d", lineNum),
					RuleID:         "SKL-004",
					Title:          "Prompt Injection / Guardrail Override Keyword",
					Severity:       model.SeverityHigh,
					Category:       model.CatPromptInjection,
					File:           filePath,
					Line:           lineNum,
					Snippet:        sanitizeSnippet(line),
					Description:    fmt.Sprintf("Found suspicious prompt instruction pattern: '%s'. This may attempt to bypass agent guardrails.", match),
					Recommendation: "Review skill instructions to ensure prompts cannot trick the model into overriding system security instructions.",
				})
				break
			}
		}

		// 5. Check for sensitive file references (ignore safe templates like .env.example)
		cleanLine := strings.ReplaceAll(line, ".env.example", "")
		cleanLine = strings.ReplaceAll(cleanLine, ".env.sample", "")
		cleanLine = strings.ReplaceAll(cleanLine, ".env.template", "")
		if match := sensitiveFilePattern.FindString(cleanLine); match != "" {
			findings = append(findings, model.Finding{
				ID:             fmt.Sprintf("SKILL-SENSFILE-%d", lineNum),
				RuleID:         "SKL-005",
				Title:          fmt.Sprintf("Sensitive Credential File Targeted: %s", match),
				Severity:       model.SeverityMedium,
				Category:       model.CatSensitiveFileRead,
				File:           filePath,
				Line:           lineNum,
				Snippet:        sanitizeSnippet(line),
				Description:    fmt.Sprintf("Skill instructions specifically target '%s'. If the agent is instructed to read this, it could be exposed in conversation context.", match),
				Recommendation: "Ensure access to credentials and .env files is masked or restricted via Samar middleware.",
			})
		}

		// 6. Check for system tag and role spoofing (token manipulation)
		if match := systemTagRegex.FindString(line); match != "" {
			findings = append(findings, model.Finding{
				ID:             fmt.Sprintf("SKILL-TAGSPOOF-%d", lineNum),
				RuleID:         "SKL-006",
				Title:          fmt.Sprintf("System Role / Delimiter Spoofing Detected: %s", match),
				Severity:       model.SeverityHigh,
				Category:       model.CatPromptInjection,
				File:           filePath,
				Line:           lineNum,
				Snippet:        sanitizeSnippet(line),
				Description:    fmt.Sprintf("Line contains privileged system/delimiter token '%s'. Attackers inject these tokens to impersonate system-level instructions and trick LLM tokenizers.", match),
				Recommendation: "Strip special tokenizer system tokens and delimit user inputs using standard markdown or xml structures.",
			})
		}

		// 7. Check for hidden HTML / CSS steganography
		if match := hiddenHtmlRegex.FindString(line); match != "" {
			findings = append(findings, model.Finding{
				ID:             fmt.Sprintf("SKILL-HIDDEN-%d", lineNum),
				RuleID:         "SKL-007",
				Title:          "Hidden Content via HTML / CSS Detected",
				Severity:       model.SeverityMedium,
				Category:       model.CatPromptInjection,
				File:           filePath,
				Line:           lineNum,
				Snippet:        sanitizeSnippet(line),
				Description:    "HTML/CSS styling appears to conceal text from human reviewers (e.g. display:none or hidden attribute) while still being ingested by the LLM.",
				Recommendation: "Remove hidden elements and ensure all prompt instructions are transparently visible.",
			})
		}

		// 8. Check for destructive execution directives
		if match := destructiveDirectiveRegex.FindString(line); match != "" {
			findings = append(findings, model.Finding{
				ID:             fmt.Sprintf("SKILL-DESTRUCT-%d", lineNum),
				RuleID:         "SKL-008",
				Title:          fmt.Sprintf("Destructive Execution Directive: %s", match),
				Severity:       model.SeverityHigh,
				Category:       model.CatExcessiveAgency,
				File:           filePath,
				Line:           lineNum,
				Snippet:        sanitizeSnippet(line),
				Description:    fmt.Sprintf("Skill instructions reference high-impact destructive commands ('%s') without explicit human-in-the-loop safeguards.", match),
				Recommendation: "Require human approval and provide safe dry-run flags for irreversible filesystem or database operations.",
			})
		}
	}

	return findings, scanner.Err()
}

func sanitizeSnippet(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		return s[:117] + "..."
	}
	return s
}
