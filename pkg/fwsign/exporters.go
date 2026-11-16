package fwsign

import (
	"encoding/json"
	"fmt"
	"strings"
)

// FormatTable generates an ANSI-compatible ASCII table representing the audit report.
func FormatTable(report *AuditReport) string {
	var sb strings.Builder

	sb.WriteString("\n========================================================================================\n")
	sb.WriteString(" LOGIHERTZ FIRMWARE SIGNING & HSM POSTURE AUDIT REPORT\n")
	sb.WriteString(fmt.Sprintf(" Policy: %s\n", report.PolicyName))
	sb.WriteString("========================================================================================\n")
	sb.WriteString(fmt.Sprintf(" %-12s | %-6s | %-8s | %-4s | %s\n", "RULE ID", "STATUS", "SEVERITY", "DED", "RULE NAME"))
	sb.WriteString("----------------------------------------------------------------------------------------\n")

	for _, f := range report.Findings {
		status := "PASS"
		dedStr := "-0"
		if !f.Passed {
			status = "FAIL"
			dedStr = fmt.Sprintf("-%d", f.Deduction)
		}
		sb.WriteString(fmt.Sprintf(" %-12s | %-6s | %-8s | %-4s | %s\n",
			f.RuleID, status, f.Severity, dedStr, f.RuleName))
	}

	sb.WriteString("========================================================================================\n")
	sb.WriteString(fmt.Sprintf(" SUMMARY: Total Rules: %d | Passed: %d | Failed: %d | Deductions: -%d\n",
		report.TotalRules, report.PassedRules, report.FailedRules, report.TotalDeductions))

	verdict := "PASS"
	if report.PostureScore < 100 || report.FailedRules > 0 {
		verdict = "FAIL"
	}
	sb.WriteString(fmt.Sprintf(" POSTURE SCORE: %d / 100 [%s]\n", report.PostureScore, verdict))
	sb.WriteString("========================================================================================\n\n")

	return sb.String()
}

// FormatJSON outputs the canonical JSON representation of the audit report.
func FormatJSON(report *AuditReport) (string, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal report json: %w", err)
	}
	return string(data), nil
}

// SarifReport represents the root OASIS SARIF v2.1.0 document.
type SarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SarifRule `json:"rules"`
}

type SarifRule struct {
	ID                   string              `json:"id"`
	Name                 string              `json:"name"`
	ShortDescription     SarifText           `json:"shortDescription"`
	Help                 SarifText           `json:"help"`
	DefaultConfiguration SarifRuleConfig     `json:"defaultConfiguration"`
	Properties           map[string][]string `json:"properties"`
}

type SarifText struct {
	Text string `json:"text"`
}

type SarifRuleConfig struct {
	Level string `json:"level"`
}

type SarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SarifText       `json:"message"`
	Locations []SarifLocation `json:"locations,omitempty"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
}

type SarifArtifactLocation struct {
	URI string `json:"uri"`
}

// FormatSARIF produces an OASIS SARIF v2.1.0 document.
func FormatSARIF(report *AuditReport) (string, error) {
	driverRules := make([]SarifRule, 0, len(report.Findings))
	results := make([]SarifResult, 0)

	for _, f := range report.Findings {
		level := "none"
		switch f.Severity {
		case SeverityCritical, SeverityHigh:
			level = "error"
		case SeverityMedium:
			level = "warning"
		case SeverityLow:
			level = "note"
		}

		driverRules = append(driverRules, SarifRule{
			ID:   f.RuleID,
			Name: f.RuleName,
			ShortDescription: SarifText{
				Text: f.RuleName,
			},
			Help: SarifText{
				Text: f.Recommendation,
			},
			DefaultConfiguration: SarifRuleConfig{
				Level: level,
			},
			Properties: map[string][]string{
				"tags": {"security", "firmware", "pkcs11", f.CWEID},
			},
		})

		if !f.Passed {
			results = append(results, SarifResult{
				RuleID: f.RuleID,
				Level:  level,
				Message: SarifText{
					Text: fmt.Sprintf("[%s] %s: %s (Deduction: -%d). Recommendation: %s",
						f.RuleID, f.RuleName, f.Details, f.Deduction, f.Recommendation),
				},
				Locations: []SarifLocation{
					{
						PhysicalLocation: SarifPhysicalLocation{
							ArtifactLocation: SarifArtifactLocation{
								URI: report.PolicyName,
							},
						},
					},
				},
			})
		}
	}

	sarifDoc := SarifReport{
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SarifRun{
			{
				Tool: SarifTool{
					Driver: SarifDriver{
						Name:           "lh-fw-sign",
						Version:        "0.1.0",
						InformationURI: "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-firmware-sign-cli",
						Rules:          driverRules,
					},
				},
				Results: results,
			},
		},
	}

	data, err := json.MarshalIndent(sarifDoc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal SARIF json: %w", err)
	}
	return string(data), nil
}
