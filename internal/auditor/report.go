package auditor

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"mcp-skill-auditor/internal/model"
)

// ANSI color codes for terminal
const (
	colorReset     = "\033[0m"
	colorRed       = "\033[1;31m"
	colorYellow    = "\033[1;33m"
	colorCyan      = "\033[1;36m"
	colorBlue      = "\033[1;34m"
	colorGreen     = "\033[1;32m"
	colorBold      = "\033[1m"
	colorDim       = "\033[2m"
	colorUnderline = "\033[4m"
)

func severityBadge(s model.Severity, useColor bool) string {
	if !useColor {
		return fmt.Sprintf("[%s]", s)
	}
	switch s {
	case model.SeverityCritical:
		return fmt.Sprintf("%s[CRITICAL]%s", colorRed, colorReset)
	case model.SeverityHigh:
		return fmt.Sprintf("%s[HIGH]%s", colorRed, colorReset)
	case model.SeverityMedium:
		return fmt.Sprintf("%s[MEDIUM]%s", colorYellow, colorReset)
	case model.SeverityLow:
		return fmt.Sprintf("%s[LOW]%s", colorCyan, colorReset)
	case model.SeverityInfo:
		return fmt.Sprintf("%s[INFO]%s", colorBlue, colorReset)
	default:
		return fmt.Sprintf("[%s]", s)
	}
}

// RenderTerminal writes an attractive terminal report with ANSI colors.
func RenderTerminal(r *model.AuditReport, w io.Writer, useColor bool) error {
	fmt.Fprintf(w, "\n")
	if useColor {
		fmt.Fprintf(w, "%s🛡️  MCP & SKILL SECURITY AUDITOR REPORT%s\n", colorBold, colorReset)
		fmt.Fprintf(w, "%s=========================================================================%s\n", colorDim, colorReset)
	} else {
		fmt.Fprintf(w, "MCP & SKILL SECURITY AUDITOR REPORT\n")
		fmt.Fprintf(w, "=========================================================================\n")
	}

	fmt.Fprintf(w, " Scanned Files : %d\n", r.Summary.TotalFilesScanned)
	fmt.Fprintf(w, " Total Findings: %d (Critical: %d, High: %d, Medium: %d, Low: %d)\n",
		r.Summary.TotalFindings,
		r.Summary.CriticalCount,
		r.Summary.HighCount,
		r.Summary.MediumCount,
		r.Summary.LowCount,
	)
	fmt.Fprintf(w, " Scan Duration : %d ms\n", r.Summary.ScanDurationMs)
	fmt.Fprintf(w, "=========================================================================\n\n")

	if len(r.Findings) == 0 {
		if useColor {
			fmt.Fprintf(w, "%s✅ No security risks or data exfiltration vectors detected!%s\n\n", colorGreen, colorReset)
		} else {
			fmt.Fprintf(w, "[OK] No security risks or data exfiltration vectors detected!\n\n")
		}
		return nil
	}

	for i, f := range r.Findings {
		badge := severityBadge(f.Severity, useColor)
		cat := string(f.Category)
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}

		if useColor {
			fmt.Fprintf(w, "%d. %s %s%s%s (%s%s%s)\n", i+1, badge, colorBold, f.Title, colorReset, colorDim, cat, colorReset)
			fmt.Fprintf(w, "   %sLocation:%s %s\n", colorDim, colorReset, loc)
			if f.Snippet != "" {
				fmt.Fprintf(w, "   %sSnippet :%s `%s`\n", colorDim, colorReset, f.Snippet)
			}
			fmt.Fprintf(w, "   %sDetail  :%s %s\n", colorDim, colorReset, f.Description)
			fmt.Fprintf(w, "   %sAction  :%s %s%s%s\n\n", colorDim, colorReset, colorGreen, f.Recommendation, colorReset)
		} else {
			fmt.Fprintf(w, "%d. %s %s (%s)\n", i+1, badge, f.Title, cat)
			fmt.Fprintf(w, "   Location: %s\n", loc)
			if f.Snippet != "" {
				fmt.Fprintf(w, "   Snippet : %s\n", f.Snippet)
			}
			fmt.Fprintf(w, "   Detail  : %s\n", f.Description)
			fmt.Fprintf(w, "   Action  : %s\n\n", f.Recommendation)
		}
	}

	return nil
}

// RenderMarkdown generates a GitHub Flavored Markdown report.
func RenderMarkdown(r *model.AuditReport, w io.Writer) error {
	var sb strings.Builder
	sb.WriteString("# 🛡️ MCP & Skill Security Audit Report\n\n")
	sb.WriteString(fmt.Sprintf("**Date:** %s  \n", r.Summary.Timestamp.Format("2006-01-02 15:04:05 MST")))
	sb.WriteString(fmt.Sprintf("**Total Files Scanned:** %d  \n", r.Summary.TotalFilesScanned))
	sb.WriteString(fmt.Sprintf("**Total Findings:** %d  \n\n", r.Summary.TotalFindings))

	sb.WriteString("### Summary Severity\n\n")
	sb.WriteString("| Critical | High | Medium | Low | Duration |\n")
	sb.WriteString("| :---: | :---: | :---: | :---: | :---: |\n")
	sb.WriteString(fmt.Sprintf("| **%d** | **%d** | %d | %d | %d ms |\n\n",
		r.Summary.CriticalCount, r.Summary.HighCount, r.Summary.MediumCount, r.Summary.LowCount, r.Summary.ScanDurationMs))

	if len(r.Findings) == 0 {
		sb.WriteString("> [!TIP]\n> **No security risks or data exfiltration vectors detected!** All scanned files passed checks.\n\n")
		_, err := io.WriteString(w, sb.String())
		return err
	}

	sb.WriteString("### Findings Detail\n\n")
	for i, f := range r.Findings {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s#L%d", f.File, f.Line)
		}

		alertType := "NOTE"
		switch f.Severity {
		case model.SeverityCritical:
			alertType = "CAUTION"
		case model.SeverityHigh:
			alertType = "WARNING"
		case model.SeverityMedium:
			alertType = "IMPORTANT"
		}

		sb.WriteString(fmt.Sprintf("#### %d. [%s] %s\n\n", i+1, f.Severity, f.Title))
		sb.WriteString(fmt.Sprintf("> [!%s]\n", alertType))
		sb.WriteString(fmt.Sprintf("> **Category:** `%s` | **Rule:** `%s`  \n", f.Category, f.RuleID))
		sb.WriteString(fmt.Sprintf("> **File:** `%s`  \n", loc))
		if f.Snippet != "" {
			sb.WriteString(fmt.Sprintf("> **Snippet:** `%s`  \n", f.Snippet))
		}
		sb.WriteString(fmt.Sprintf("> **Description:** %s  \n", f.Description))
		sb.WriteString(fmt.Sprintf("> **Recommendation:** %s\n\n", f.Recommendation))
	}

	_, err := io.WriteString(w, sb.String())
	return err
}

// RenderJSON outputs indented JSON representation of the report.
func RenderJSON(r *model.AuditReport, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
