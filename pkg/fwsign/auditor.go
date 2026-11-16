package fwsign

import (
	"encoding/json"
	"fmt"
	"os"
)

// FirmwareSigningPolicy defines the configuration schema for auditing firmware signing posture.
type FirmwareSigningPolicy struct {
	PolicyName                    string `json:"policy_name"`
	AllowPkcs1v15Padding          bool   `json:"allow_pkcs1v15_padding"`
	AllowSha1OrMd5                bool   `json:"allow_sha1_or_md5"`
	MinRsaKeyBits                 int    `json:"min_rsa_key_bits"`
	RequirePkcs11Hsm              bool   `json:"require_pkcs11_hsm"`
	EnforceCkaSensitive           bool   `json:"enforce_cka_sensitive"`
	EnforceCkaNonExtractable      bool   `json:"enforce_cka_non_extractable"`
	RequireRfc3161Timestamp       bool   `json:"require_rfc3161_timestamp"`
	EnforceCodesigningEku         bool   `json:"enforce_codesigning_eku"`
	BindSvnInSignature            bool   `json:"bind_svn_in_signature"`
	BindHwCompatID                bool   `json:"bind_hw_compat_id"`
	AllowPinViaCliArgv            bool   `json:"allow_pin_via_cli_argv"`
	HsmMaxPinRetries              int    `json:"hsm_max_pin_retries"`
	RequireMOfNQuorum             bool   `json:"require_m_of_n_quorum"`
	MinQuorumApprovers            int    `json:"min_quorum_approvers"`
	CheckCertRevocation           bool   `json:"check_cert_revocation"`
	MaxLeafCertValidityDays       int    `json:"max_leaf_cert_validity_days"`
	RsaPssSaltEqualsHash          bool   `json:"rsa_pss_salt_equals_hash"`
	HybridDualSignatureEnabled    bool   `json:"hybrid_dual_signature_enabled"`
	AutoLogoutHsmSession          bool   `json:"auto_logout_hsm_session"`
	HsmSessionTimeoutSec          int    `json:"hsm_session_timeout_sec"`
	TransparencyLogReceiptEnabled bool   `json:"transparency_log_receipt_enabled"`
}

// Severity levels
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// AuditFinding encapsulates the result of evaluating a single rule.
type AuditFinding struct {
	RuleID         string   `json:"rule_id"`
	RuleName       string   `json:"rule_name"`
	CWEID          string   `json:"cwe_id"`
	Severity       Severity `json:"severity"`
	Deduction      int      `json:"deduction"`
	Passed         bool     `json:"passed"`
	Details        string   `json:"details"`
	Recommendation string   `json:"recommendation"`
}

// AuditReport aggregates all findings and computes the final posture score.
type AuditReport struct {
	PolicyName      string         `json:"policy_name"`
	TotalRules      int            `json:"total_rules"`
	PassedRules     int            `json:"passed_rules"`
	FailedRules     int            `json:"failed_rules"`
	TotalDeductions int            `json:"total_deductions"`
	PostureScore    int            `json:"posture_score"`
	Findings        []AuditFinding `json:"findings"`
}

// ParsePolicyFile reads and unmarshals a JSON policy manifest.
func ParsePolicyFile(path string) (*FirmwareSigningPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	var policy FirmwareSigningPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("parse policy json: %w", err)
	}
	return &policy, nil
}

// EvaluatePosture audits the policy against the 10 Logihertz normative firmware signing rules.
func EvaluatePosture(policy *FirmwareSigningPolicy) *AuditReport {
	report := &AuditReport{
		PolicyName: policy.PolicyName,
		TotalRules: 10,
		Findings:   make([]AuditFinding, 0, 10),
	}

	// Rule 1: LH-FWS-001 (CRITICAL, 25, CWE-327)
	{
		f := AuditFinding{
			RuleID:         "LH-FWS-001",
			RuleName:       "Cryptographic Algorithm Modernity & Padding Invariant",
			CWEID:          "CWE-327",
			Severity:       SeverityCritical,
			Deduction:      25,
			Recommendation: "Mandate RSASSA-PSS (salt length = hash length) and Ed25519; prohibit PKCS#1 v1.5 padding and SHA-1/MD5; enforce RSA >= 3072 bits.",
		}
		if policy.AllowPkcs1v15Padding || policy.AllowSha1OrMd5 || policy.MinRsaKeyBits < 3072 {
			f.Passed = false
			f.Details = fmt.Sprintf("Weak algorithm or padding permitted: PKCS#1 v1.5=%v, SHA-1/MD5=%v, MinRSAKeyBits=%d (< 3072).",
				policy.AllowPkcs1v15Padding, policy.AllowSha1OrMd5, policy.MinRsaKeyBits)
			report.TotalDeductions += f.Deduction
			report.FailedRules++
		} else {
			f.Passed = true
			f.Details = "Modern cryptographic primitives enforced (Ed25519 & RSA-PSS >= 3072 bits, no legacy padding or weak hashes)."
			report.PassedRules++
		}
		report.Findings = append(report.Findings, f)
	}

	// Rule 2: LH-FWS-002 (CRITICAL, 25, CWE-522)
	{
		f := AuditFinding{
			RuleID:         "LH-FWS-002",
			RuleName:       "PKCS#11 HSM Hardware Key Isolation & Non-Extractability Guard",
			CWEID:          "CWE-522",
			Severity:       SeverityCritical,
			Deduction:      25,
			Recommendation: "Store private signing keys exclusively in FIPS 140-3 Level 3 PKCS#11 HSMs with CKA_SENSITIVE=true and CKA_EXTRACTABLE=false.",
		}
		if !policy.RequirePkcs11Hsm || !policy.EnforceCkaSensitive || !policy.EnforceCkaNonExtractable {
			f.Passed = false
			f.Details = fmt.Sprintf("Signing keys not strictly isolated in HSM: RequirePKCS11=%v, CKA_SENSITIVE=%v, CKA_NON_EXTRACTABLE=%v.",
				policy.RequirePkcs11Hsm, policy.EnforceCkaSensitive, policy.EnforceCkaNonExtractable)
			report.TotalDeductions += f.Deduction
			report.FailedRules++
		} else {
			f.Passed = true
			f.Details = "Private keys enforced in PKCS#11 HSM with hardware non-extractability and sensitivity invariants active."
			report.PassedRules++
		}
		report.Findings = append(report.Findings, f)
	}

	// Rule 3: LH-FWS-003 (CRITICAL, 25, CWE-347)
	{
		f := AuditFinding{
			RuleID:         "LH-FWS-003",
			RuleName:       "RFC 3161 Cryptographic Timestamp & Code-Signing EKU Enforcement",
			CWEID:          "CWE-347",
			Severity:       SeverityCritical,
			Deduction:      25,
			Recommendation: "Enforce RFC 3161 cryptographic Time-Stamp Authority (TSA) tokens and mandate ExtKeyUsageCodeSigning (1.3.6.1.5.5.7.3.3).",
		}
		if !policy.RequireRfc3161Timestamp || !policy.EnforceCodesigningEku {
			f.Passed = false
			f.Details = fmt.Sprintf("Missing timestamping or code-signing EKU checks: RequireRFC3161=%v, EnforceCodeSigningEKU=%v.",
				policy.RequireRfc3161Timestamp, policy.EnforceCodesigningEku)
			report.TotalDeductions += f.Deduction
			report.FailedRules++
		} else {
			f.Passed = true
			f.Details = "RFC 3161 timestamping and X.509 code-signing EKU validation actively enforced."
			report.PassedRules++
		}
		report.Findings = append(report.Findings, f)
	}

	// Rule 4: LH-FWS-004 (HIGH, 10, CWE-693)
	{
		f := AuditFinding{
			RuleID:         "LH-FWS-004",
			RuleName:       "Anti-Rollback SVN & Hardware Target ID Cryptographic Binding",
			CWEID:          "CWE-693",
			Severity:       SeverityHigh,
			Deduction:      10,
			Recommendation: "Bind monotonic Security Version Number (SVN >= 1) and canonical HardwareCompatID into authenticated firmware headers.",
		}
		if !policy.BindSvnInSignature || !policy.BindHwCompatID {
			f.Passed = false
			f.Details = fmt.Sprintf("Firmware header missing rollback or board identity binding: BindSVN=%v, BindHwCompatID=%v.",
				policy.BindSvnInSignature, policy.BindHwCompatID)
			report.TotalDeductions += f.Deduction
			report.FailedRules++
		} else {
			f.Passed = true
			f.Details = "Monotonic anti-rollback SVN and target hardware compatibility identifier cryptographically bound in signature."
			report.PassedRules++
		}
		report.Findings = append(report.Findings, f)
	}

	// Rule 5: LH-FWS-005 (HIGH, 10, CWE-307)
	{
		f := AuditFinding{
			RuleID:         "LH-FWS-005",
			RuleName:       "HSM PIN Ingestion Hygiene & Brute-Force Lockout Defense",
			CWEID:          "CWE-307",
			Severity:       SeverityHigh,
			Deduction:      10,
			Recommendation: "Prohibit passing HSM PINs via command-line argv (process table leak) and enforce hardware PIN lockout after <= 5 consecutive failed attempts.",
		}
		if policy.AllowPinViaCliArgv || policy.HsmMaxPinRetries > 5 {
			f.Passed = false
			f.Details = fmt.Sprintf("Insecure PIN handling: AllowPinViaCliArgv=%v, HsmMaxPinRetries=%d (> 5).",
				policy.AllowPinViaCliArgv, policy.HsmMaxPinRetries)
			report.TotalDeductions += f.Deduction
			report.FailedRules++
		} else {
			f.Passed = true
			f.Details = "HSM PIN argv leaks prohibited and brute-force lockout threshold safely bounded (<= 5)."
			report.PassedRules++
		}
		report.Findings = append(report.Findings, f)
	}

	// Rule 6: LH-FWS-006 (HIGH, 10, CWE-284)
	{
		f := AuditFinding{
			RuleID:         "LH-FWS-006",
			RuleName:       "Dual-Custody M-of-N Multi-Party Approval Quorum Enforcement",
			CWEID:          "CWE-284",
			Severity:       SeverityHigh,
			Deduction:      10,
			Recommendation: "Require M-of-N multi-party authorization quorum (minimum 2 approvers) for production firmware release ceremonies.",
		}
		if !policy.RequireMOfNQuorum || policy.MinQuorumApprovers < 2 {
			f.Passed = false
			f.Details = fmt.Sprintf("Single-operator signing allowed without quorum: RequireMOfN=%v, MinQuorumApprovers=%d (< 2).",
				policy.RequireMOfNQuorum, policy.MinQuorumApprovers)
			report.TotalDeductions += f.Deduction
			report.FailedRules++
		} else {
			f.Passed = true
			f.Details = fmt.Sprintf("Dual-custody M-of-N quorum enforced with %d required approvers.", policy.MinQuorumApprovers)
			report.PassedRules++
		}
		report.Findings = append(report.Findings, f)
	}

	// Rule 7: LH-FWS-007 (HIGH, 10, CWE-295)
	{
		f := AuditFinding{
			RuleID:         "LH-FWS-007",
			RuleName:       "Certificate Revocation Checking & Maximum Validity Ceiling Guard",
			CWEID:          "CWE-295",
			Severity:       SeverityHigh,
			Deduction:      10,
			Recommendation: "Enforce real-time CRL/OCSP revocation verification and restrict leaf code-signing certificate lifespan to <= 397 days.",
		}
		if !policy.CheckCertRevocation || policy.MaxLeafCertValidityDays > 397 {
			f.Passed = false
			f.Details = fmt.Sprintf("Certificate lifecycle unmanaged: CheckCertRevocation=%v, MaxLeafCertValidityDays=%d (> 397).",
				policy.CheckCertRevocation, policy.MaxLeafCertValidityDays)
			report.TotalDeductions += f.Deduction
			report.FailedRules++
		} else {
			f.Passed = true
			f.Details = fmt.Sprintf("Certificate revocation checks active and validity window bounded (%d <= 397 days).", policy.MaxLeafCertValidityDays)
			report.PassedRules++
		}
		report.Findings = append(report.Findings, f)
	}

	// Rule 8: LH-FWS-008 (MEDIUM, 4, CWE-330)
	{
		f := AuditFinding{
			RuleID:         "LH-FWS-008",
			RuleName:       "RSASSA-PSS Salt Length Invariant & Dual-Algorithm Redundancy",
			CWEID:          "CWE-330",
			Severity:       SeverityMedium,
			Deduction:      4,
			Recommendation: "Configure RSA-PSS salt length equal to hash output length and enable hybrid Ed25519 + RSA-PSS dual-algorithm signatures.",
		}
		if !policy.RsaPssSaltEqualsHash || !policy.HybridDualSignatureEnabled {
			f.Passed = false
			f.Details = fmt.Sprintf("Non-standard salt or missing dual algorithm: RsaPssSaltEqualsHash=%v, HybridDualSignatureEnabled=%v.",
				policy.RsaPssSaltEqualsHash, policy.HybridDualSignatureEnabled)
			report.TotalDeductions += f.Deduction
			report.FailedRules++
		} else {
			f.Passed = true
			f.Details = "Standardized RSA-PSS salt length and hybrid Ed25519 + RSA-PSS redundancy confirmed."
			report.PassedRules++
		}
		report.Findings = append(report.Findings, f)
	}

	// Rule 9: LH-FWS-009 (MEDIUM, 4, CWE-226)
	{
		f := AuditFinding{
			RuleID:         "LH-FWS-009",
			RuleName:       "HSM Ephemeral Session Teardown & Inactivity Timeout Guard",
			CWEID:          "CWE-226",
			Severity:       SeverityMedium,
			Deduction:      4,
			Recommendation: "Automatically close and logout HSM sessions immediately following signing operations and enforce timeout <= 60 seconds.",
		}
		if !policy.AutoLogoutHsmSession || policy.HsmSessionTimeoutSec > 60 {
			f.Passed = false
			f.Details = fmt.Sprintf("HSM session persistence risks: AutoLogoutHsmSession=%v, HsmSessionTimeoutSec=%d (> 60).",
				policy.AutoLogoutHsmSession, policy.HsmSessionTimeoutSec)
			report.TotalDeductions += f.Deduction
			report.FailedRules++
		} else {
			f.Passed = true
			f.Details = fmt.Sprintf("Ephemeral HSM session logout enforced with inactivity timeout %d s <= 60 s.", policy.HsmSessionTimeoutSec)
			report.PassedRules++
		}
		report.Findings = append(report.Findings, f)
	}

	// Rule 10: LH-FWS-010 (LOW, 1, CWE-778)
	{
		f := AuditFinding{
			RuleID:         "LH-FWS-010",
			RuleName:       "Append-Only Signing Transparency Log & Provenance Audit Trail",
			CWEID:          "CWE-778",
			Severity:       SeverityLow,
			Deduction:      1,
			Recommendation: "Publish cryptographic signing receipts and firmware build provenance to an append-only transparency log.",
		}
		if !policy.TransparencyLogReceiptEnabled {
			f.Passed = false
			f.Details = "Transparency log receipt generation is disabled; firmware releases lack public verifiable audit trail."
			report.TotalDeductions += f.Deduction
			report.FailedRules++
		} else {
			f.Passed = true
			f.Details = "Append-only signing transparency log receipts enabled for cryptographic build provenance."
			report.PassedRules++
		}
		report.Findings = append(report.Findings, f)
	}

	// Score Calculation: S_posture = max(0, 100 - sum(Deductions))
	if report.TotalDeductions >= 100 {
		report.PostureScore = 0
	} else {
		report.PostureScore = 100 - report.TotalDeductions
	}

	return report
}
