package auditor

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mcp-skill-auditor/internal/scanners"
)

type AuditOptions struct {
	ConfigFiles []string
	SkillDirs   []string
	TargetDirs  []string
	FailOn      Severity
}

type Engine struct {
	opts AuditOptions
}

func NewEngine(opts AuditOptions) *Engine {
	return &Engine{opts: opts}
}

func (e *Engine) Run() (*AuditReport, error) {
	start := time.Now()
	report := &AuditReport{
		Summary: ScanSummary{
			Timestamp: start,
		},
	}

	scannedFiles := make(map[string]bool)

	// 1. Scan MCP Configs
	var allConfigs []string
	for _, c := range e.opts.ConfigFiles {
		if c != "" {
			allConfigs = append(allConfigs, c)
		}
	}

	for _, cfgPath := range allConfigs {
		if _, err := os.Stat(cfgPath); err == nil {
			scannedFiles[cfgPath] = true
			findings, err := scanners.ScanMCPConfig(cfgPath)
			if err != nil {
				// Never let an unparseable config look identical to a clean
				// one. Surface it as a finding and warn on stderr.
				report.AddFinding(Finding{
					ID:             fmt.Sprintf("CFG-PARSE-%s", cfgPath),
					RuleID:         "CFG-000",
					Title:          "MCP Config Could Not Be Parsed",
					Description:    fmt.Sprintf("The config file was found but could not be read or parsed, so it was NOT audited: %v", err),
					Severity:       SeverityLow,
					Category:       CatSecurityConfig,
					File:           cfgPath,
					Recommendation: "Verify the file is valid JSON (and free of encoding issues) so it can be scanned for secrets and risks.",
				})
				fmt.Fprintf(os.Stderr, "warning: skipped unparseable config %s: %v\n", cfgPath, err)
				continue
			}
			for _, f := range findings {
				report.AddFinding(f)
			}
		}
	}

	// 2. Scan Skill Directories
	for _, skillDir := range e.opts.SkillDirs {
		if skillDir == "" {
			continue
		}
		if _, err := os.Stat(skillDir); os.IsNotExist(err) {
			continue
		}

		err := filepath.WalkDir(skillDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // Skip unreadable paths
			}
			if d.IsDir() {
				name := d.Name()
				if name == ".git" || name == "node_modules" || name == "vendor" || name == ".venv" || name == "__pycache__" || name == "dist" || name == "bin" || name == "mcp-skill-auditor" {
					return filepath.SkipDir
				}
				return nil
			}

			ext := strings.ToLower(filepath.Ext(path))
			scannedFiles[path] = true

			// Scan markdown prompts / skills
			if ext == ".md" || ext == ".markdown" {
				findings, err := scanners.ScanSkillFile(path)
				if err == nil {
					for _, f := range findings {
						report.AddFinding(f)
					}
				}
			}

			// Scan helper scripts
			if isSourceExt(ext) {
				findings, err := scanners.ScanSourceFile(path)
				if err == nil {
					for _, f := range findings {
						report.AddFinding(f)
					}
				}
			}

			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed scanning skill dir %s: %w", skillDir, err)
		}
	}

	// 3. Scan Custom Target Directories / MCP sources
	for _, target := range e.opts.TargetDirs {
		if target == "" {
			continue
		}
		fi, err := os.Stat(target)
		if os.IsNotExist(err) {
			continue
		}

		if !fi.IsDir() {
			scannedFiles[target] = true
			ext := strings.ToLower(filepath.Ext(target))
			if ext == ".md" {
				findings, _ := scanners.ScanSkillFile(target)
				for _, f := range findings {
					report.AddFinding(f)
				}
			} else if isSourceExt(ext) {
				findings, _ := scanners.ScanSourceFile(target)
				for _, f := range findings {
					report.AddFinding(f)
				}
			}
			continue
		}

		err = filepath.WalkDir(target, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				name := d.Name()
				if name == ".git" || name == "node_modules" || name == "vendor" || name == ".venv" || name == "__pycache__" || name == "dist" || name == "bin" || name == "mcp-skill-auditor" {
					return filepath.SkipDir
				}
				return nil
			}

			ext := strings.ToLower(filepath.Ext(path))
			scannedFiles[path] = true

			if ext == ".md" {
				findings, _ := scanners.ScanSkillFile(path)
				for _, f := range findings {
					report.AddFinding(f)
				}
			} else if isSourceExt(ext) {
				findings, _ := scanners.ScanSourceFile(path)
				for _, f := range findings {
					report.AddFinding(f)
				}
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed scanning target %s: %w", target, err)
		}
	}

	report.Summary.TotalFilesScanned = len(scannedFiles)
	report.Summary.ScanDurationMs = time.Since(start).Milliseconds()

	return report, nil
}

func isSourceExt(ext string) bool {
	switch ext {
	case ".go", ".py", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".sh", ".bash", ".ps1", ".bat", ".cmd":
		return true
	default:
		return false
	}
}
