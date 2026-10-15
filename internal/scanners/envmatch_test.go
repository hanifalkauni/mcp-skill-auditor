package scanners_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mcp-skill-auditor/internal/model"
	"mcp-skill-auditor/internal/scanners"
)

// Verifies .env filename matching no longer fires on os.environ/process.env/.environment
// but still fires on real .env file references.
func TestEnvFalsePositiveGuard(t *testing.T) {
	cases := []struct {
		line       string
		wantSKL005 bool
	}{
		{"read via os.environ[\"TABLE_NAME\"]", false},
		{"globals mutated via os.environ", false},
		{"the project .environment settings", false},
		{"copy your secrets into .env", true},
		{"configure `.env.local` for dev", true},
		{"never commit the .env file", true},
		{"load `.env.production`", true},
	}

	for _, c := range cases {
		tmp := t.TempDir()
		p := filepath.Join(tmp, "SKILL.md")
		if err := os.WriteFile(p, []byte("# T\n\n"+c.line+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
		findings, err := scanners.ScanSkillFile(p)
		if err != nil {
			t.Fatal(err)
		}
		got := false
		for _, f := range findings {
			if f.RuleID == "SKL-005" {
				got = true
			}
		}
		if got != c.wantSKL005 {
			t.Errorf("line %q: SKL-005 got=%v want=%v (findings: %v)", c.line, got, c.wantSKL005, summarizeRuleIDs(findings))
		}
	}
}

// Verifies SRC-SENS-FILE no longer fires on os.environ string literals
// but still fires on real .env / key file paths in quotes.
func TestSrcSensFileFalsePositiveGuard(t *testing.T) {
	cases := []struct {
		code         string
		wantSensFile bool
	}{
		{`val = os.environ["TABLE_NAME"]`, false},
		{`cfg = process.env["PORT"]`, false},
		{`paths = [".kiro/crew/.env"]`, true},
		{`open(".env.local")`, true},
		{`key = "~/.ssh/id_rsa"`, true},
		{`creds = "~/.aws/credentials"`, true},
	}

	for _, c := range cases {
		tmp := t.TempDir()
		p := filepath.Join(tmp, "snippet.py")
		if err := os.WriteFile(p, []byte(c.code+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
		findings, err := scanners.ScanSourceFile(p)
		if err != nil {
			t.Fatal(err)
		}
		got := false
		for _, f := range findings {
			if f.RuleID == "SRC-SENS-FILE" {
				got = true
			}
		}
		if got != c.wantSensFile {
			t.Errorf("code %q: SRC-SENS-FILE got=%v want=%v (findings: %v)", c.code, got, c.wantSensFile, summarizeRuleIDs(findings))
		}
	}
}

func summarizeRuleIDs(fs []model.Finding) string {
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.RuleID)
	}
	return strings.Join(ids, ",")
}
