package model

import (
	"fmt"
	"strings"
	"time"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

func (s Severity) Weight() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

func ParseSeverity(s string) (Severity, error) {
	upper := strings.ToUpper(strings.TrimSpace(s))
	switch Severity(upper) {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return Severity(upper), nil
	default:
		return "", fmt.Errorf("invalid severity level: %s (valid: CRITICAL, HIGH, MEDIUM, LOW, INFO)", s)
	}
}

type Category string

const (
	CatSecretLeak        Category = "SECRET_LEAK"
	CatNetworkEgress     Category = "NETWORK_EGRESS"
	CatPromptInjection   Category = "PROMPT_INJECTION"
	CatSuspiciousCommand Category = "SUSPICIOUS_EXECUTION"
	CatSupplyChainRisk   Category = "SUPPLY_CHAIN_RISK"
	CatSensitiveFileRead Category = "SENSITIVE_FILE_ACCESS"
	CatSSRF              Category = "SSRF_PROBING"
	CatPathTraversal     Category = "PATH_TRAVERSAL"
	CatSecurityConfig    Category = "SECURITY_CONFIG"
	CatExcessiveAgency   Category = "EXCESSIVE_AGENCY"
)

type Finding struct {
	ID             string   `json:"id"`
	RuleID         string   `json:"rule_id"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Severity       Severity `json:"severity"`
	Category       Category `json:"category"`
	File           string   `json:"file"`
	Line           int      `json:"line,omitempty"`
	Snippet        string   `json:"snippet,omitempty"`
	Recommendation string   `json:"recommendation"`
}

type ScanSummary struct {
	TotalFilesScanned int       `json:"total_files_scanned"`
	TotalFindings     int       `json:"total_findings"`
	CriticalCount     int       `json:"critical_count"`
	HighCount         int       `json:"high_count"`
	MediumCount       int       `json:"medium_count"`
	LowCount          int       `json:"low_count"`
	InfoCount         int       `json:"info_count"`
	ScanDurationMs    int64     `json:"scan_duration_ms"`
	Timestamp         time.Time `json:"timestamp"`
}

type AuditReport struct {
	Summary  ScanSummary `json:"summary"`
	Findings []Finding   `json:"findings"`
}

func (r *AuditReport) AddFinding(f Finding) {
	r.Findings = append(r.Findings, f)
	r.Summary.TotalFindings++
	switch f.Severity {
	case SeverityCritical:
		r.Summary.CriticalCount++
	case SeverityHigh:
		r.Summary.HighCount++
	case SeverityMedium:
		r.Summary.MediumCount++
	case SeverityLow:
		r.Summary.LowCount++
	case SeverityInfo:
		r.Summary.InfoCount++
	}
}
