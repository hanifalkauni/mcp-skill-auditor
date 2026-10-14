package auditor

import "mcp-skill-auditor/internal/model"

type Severity = model.Severity

const (
	SeverityCritical = model.SeverityCritical
	SeverityHigh     = model.SeverityHigh
	SeverityMedium   = model.SeverityMedium
	SeverityLow      = model.SeverityLow
	SeverityInfo     = model.SeverityInfo
)

var ParseSeverity = model.ParseSeverity

type Category = model.Category

const (
	CatSecretLeak        = model.CatSecretLeak
	CatNetworkEgress     = model.CatNetworkEgress
	CatPromptInjection   = model.CatPromptInjection
	CatSuspiciousCommand = model.CatSuspiciousCommand
	CatSupplyChainRisk   = model.CatSupplyChainRisk
	CatSensitiveFileRead = model.CatSensitiveFileRead
	CatSSRF              = model.CatSSRF
	CatPathTraversal     = model.CatPathTraversal
	CatSecurityConfig    = model.CatSecurityConfig
	CatExcessiveAgency   = model.CatExcessiveAgency
)

type Finding = model.Finding
type ScanSummary = model.ScanSummary
type AuditReport = model.AuditReport
