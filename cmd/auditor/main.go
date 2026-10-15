package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"mcp-skill-auditor/internal/auditor"
)

var (
	version = "1.0.0"
)

func main() {
	configFlag := flag.String("config", "", "Path to mcp_config.json (auto-detected if omitted)")
	skillsFlag := flag.String("skills", "", "Comma-separated list of skill directory paths to scan")
	targetFlag := flag.String("target", "", "Comma-separated list of additional MCP code directories or script files to scan")
	formatFlag := flag.String("format", "terminal", "Output format: terminal | markdown | json")
	outFlag := flag.String("out", "", "File path to write report output (default: stdout)")
	noColorFlag := flag.Bool("no-color", false, "Disable ANSI colors in terminal output")
	failOnFlag := flag.String("fail-on", "", "Exit with status code 1 if findings reach or exceed severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
	versionFlag := flag.Bool("v", false, "Print auditor version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "MCP & Skill Security Auditor v%s\n", version)
		fmt.Fprintf(os.Stderr, "Scans MCP configurations, local MCP server code, and agent skills for data leaks and security risks.\n\n")
		fmt.Fprintf(os.Stderr, "Usage: mcp-skill-auditor [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Auto-scan installed MCP config and standard skill directories\n")
		fmt.Fprintf(os.Stderr, "  mcp-skill-auditor\n\n")
		fmt.Fprintf(os.Stderr, "  # Scan specific MCP server code and generate a Markdown report\n")
		fmt.Fprintf(os.Stderr, "  mcp-skill-auditor -target ./my-mcp-server -format markdown -out report.md\n\n")
		fmt.Fprintf(os.Stderr, "  # CI / Pre-commit mode: Fail if High or Critical leaks are detected\n")
		fmt.Fprintf(os.Stderr, "  mcp-skill-auditor -fail-on HIGH\n")
	}

	flag.Parse()

	if *versionFlag {
		fmt.Printf("mcp-skill-auditor v%s\n", version)
		return
	}

	homeDir, _ := os.UserHomeDir()

	// 1. Resolve MCP Configs
	var configFiles []string
	if *configFlag != "" {
		configFiles = append(configFiles, *configFlag)
	} else if homeDir != "" {
		candidates := []string{
			// Workspace configs
			"mcp_config.json",
			"mcp.json",
			filepath.Join(".kiro", "settings", "mcp.json"),
			filepath.Join(".kiro", "mcp.json"),
			filepath.Join(".cursor", "mcp.json"),
			filepath.Join(".gemini", "config", "mcp_config.json"),
			// Global Kiro configs
			filepath.Join(homeDir, ".kiro", "settings", "mcp.json"),
			filepath.Join(homeDir, ".kiro", "mcp.json"),
			// Global Gemini / Antigravity configs
			filepath.Join(homeDir, ".gemini", "config", "mcp_config.json"),
			filepath.Join(homeDir, ".config", "antigravity", "mcp_config.json"),
			// Cursor
			filepath.Join(homeDir, ".cursor", "mcp.json"),
			// Claude Desktop
			filepath.Join(homeDir, "AppData", "Roaming", "Claude", "claude_desktop_config.json"),
			filepath.Join(homeDir, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
			filepath.Join(homeDir, ".config", "Claude", "claude_desktop_config.json"),
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				configFiles = append(configFiles, c)
			}
		}
	}

	// 2. Resolve Skill directories
	var skillDirs []string
	if *skillsFlag != "" {
		for _, s := range strings.Split(*skillsFlag, ",") {
			trimmed := strings.TrimSpace(s)
			if trimmed != "" {
				skillDirs = append(skillDirs, trimmed)
			}
		}
	} else {
		// Auto-discover default skill paths across Antigravity, Kiro, Cursor, and workspace
		candidates := []string{
			filepath.Join(".agents", "skills"),
			filepath.Join("..", ".agents", "skills"),
			filepath.Join(".kiro", "skills"),
			filepath.Join(".kiro", "crew", "skills"),
			filepath.Join(homeDir, ".kiro", "crew", "skills"),
			filepath.Join(homeDir, ".kiro", "skills"),
			filepath.Join(homeDir, ".gemini", "config", "skills"),
			filepath.Join(homeDir, ".gemini", "antigravity-ide", "builtin", "skills"),
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				skillDirs = append(skillDirs, c)
			}
		}
	}

	// 3. Resolve target directories
	var targetDirs []string
	if *targetFlag != "" {
		for _, t := range strings.Split(*targetFlag, ",") {
			trimmed := strings.TrimSpace(t)
			if trimmed != "" {
				targetDirs = append(targetDirs, trimmed)
			}
		}
	}

	// Validate fail-on level if specified
	var failOn auditor.Severity
	if *failOnFlag != "" {
		parsed, err := auditor.ParseSeverity(*failOnFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
		failOn = parsed
	}

	engine := auditor.NewEngine(auditor.AuditOptions{
		ConfigFiles: configFiles,
		SkillDirs:   skillDirs,
		TargetDirs:  targetDirs,
		FailOn:      failOn,
	})

	report, err := engine.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Audit error: %v\n", err)
		os.Exit(2)
	}

	// Determine output destination
	outWriter := os.Stdout
	if *outFlag != "" {
		f, err := os.Create(*outFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create output file %s: %v\n", *outFlag, err)
			os.Exit(2)
		}
		defer f.Close()
		outWriter = f
	}

	// Render output
	useColor := !*noColorFlag && *outFlag == ""
	switch strings.ToLower(*formatFlag) {
	case "markdown", "md":
		if err := auditor.RenderMarkdown(report, outWriter); err != nil {
			fmt.Fprintf(os.Stderr, "Render error: %v\n", err)
		}
	case "json":
		if err := auditor.RenderJSON(report, outWriter); err != nil {
			fmt.Fprintf(os.Stderr, "Render error: %v\n", err)
		}
	default:
		if err := auditor.RenderTerminal(report, outWriter, useColor); err != nil {
			fmt.Fprintf(os.Stderr, "Render error: %v\n", err)
		}
	}

	if *outFlag != "" {
		fmt.Fprintf(os.Stderr, "Report successfully generated to: %s\n", *outFlag)
	}

	// Check exit code for threshold failure
	if failOn != "" {
		for _, f := range report.Findings {
			if f.Severity.Weight() >= failOn.Weight() {
				fmt.Fprintf(os.Stderr, "\n[FAIL] Audit failed: Found %s finding (%s) exceeding threshold %s\n", f.Severity, f.Title, failOn)
				os.Exit(1)
			}
		}
	}
}
