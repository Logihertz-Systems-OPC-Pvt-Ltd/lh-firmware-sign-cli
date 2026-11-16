package fwsign_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-firmware-sign-cli/pkg/fwsign"
)

// ----------------------------------------------------------------------------
// SUITE 1: Hybrid Ed25519 + RSA-PSS Signing, Trailer & Tamper Detection
// ----------------------------------------------------------------------------

func TestFirmwareHeaderCanonical(t *testing.T) {
	h := &fwsign.FirmwareHeaderV1{
		Magic:            fwsign.TrailerMagic,
		FormatVersion:    1,
		SVN:              5,
		HardwareCompatID: "tegra234-orin",
		ImageSize:        1024,
		ImageSHA256:      strings.Repeat("a", 64),
		ImageSHA384:      strings.Repeat("b", 96),
	}

	canBytes := h.CanonicalBytes()
	if len(canBytes) == 0 {
		t.Fatal("canonical bytes should not be empty")
	}

	preimage := fwsign.ComputeSigningPreimage(h)
	if len(preimage) != 48 { // SHA-384 output length
		t.Fatalf("expected 48-byte preimage, got %d", len(preimage))
	}
}

func TestHybridSignAndVerifySuccess(t *testing.T) {
	firmware := []byte("LOGIHERTZ_SECURE_FIRMWARE_PAYLOAD_V1")

	// Generate keys and certs
	_, caCert, rsaKey, leafCert, caPEM, leafPEM, err := fwsign.GenerateCodeSigningCAAndLeaf(365)
	if err != nil {
		t.Fatalf("generate ca/leaf: %v", err)
	}

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}

	tsa, err := fwsign.NewTsaAuthority()
	if err != nil {
		t.Fatalf("new tsa: %v", err)
	}

	// Sign
	receipt, err := fwsign.SignFirmware(firmware, 3, "tegra234-orin", edKey, rsaKey, []string{leafPEM, caPEM}, tsa)
	if err != nil {
		t.Fatalf("sign firmware: %v", err)
	}
	if receipt == nil {
		t.Fatal("receipt is nil")
	}
	if receipt.Header.SVN != 3 {
		t.Errorf("expected SVN 3, got %d", receipt.Header.SVN)
	}
	if receipt.Header.HardwareCompatID != "tegra234-orin" {
		t.Errorf("expected HW ID tegra234-orin, got %s", receipt.Header.HardwareCompatID)
	}
	if receipt.TimestampToken == nil {
		t.Fatal("expected timestamp token in receipt")
	}

	// Verify
	err = fwsign.VerifyFirmwareReceipt(firmware, receipt, 3, "tegra234-orin", caCert, tsa.Cert)
	if err != nil {
		t.Fatalf("verify firmware receipt failed: %v", err)
	}

	// Verify with lower minSVN (anti-rollback should pass)
	err = fwsign.VerifyFirmwareReceipt(firmware, receipt, 1, "tegra234-orin", caCert, tsa.Cert)
	if err != nil {
		t.Errorf("verify with minSVN 1 failed: %v", err)
	}

	_ = leafCert
}

func TestAntiRollbackSVNFailure(t *testing.T) {
	firmware := []byte("FIRMWARE_ROLLBACK_TEST")
	_, caCert, rsaKey, _, caPEM, leafPEM, _ := fwsign.GenerateCodeSigningCAAndLeaf(365)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	tsa, _ := fwsign.NewTsaAuthority()

	receipt, _ := fwsign.SignFirmware(firmware, 2, "tegra234-orin", edKey, rsaKey, []string{leafPEM, caPEM}, tsa)

	// Attempt verification with minSVN 3 (higher than 2) -> must fail!
	err := fwsign.VerifyFirmwareReceipt(firmware, receipt, 3, "tegra234-orin", caCert, tsa.Cert)
	if err == nil {
		t.Fatal("expected verification to fail due to anti-rollback check (receipt SVN 2 < minSVN 3)")
	}
	if !strings.Contains(err.Error(), "anti-rollback check failed") {
		t.Errorf("expected anti-rollback error message, got: %v", err)
	}
}

func TestHardwareCompatIDMismatch(t *testing.T) {
	firmware := []byte("FIRMWARE_HWID_TEST")
	_, caCert, rsaKey, _, caPEM, leafPEM, _ := fwsign.GenerateCodeSigningCAAndLeaf(365)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	tsa, _ := fwsign.NewTsaAuthority()

	receipt, _ := fwsign.SignFirmware(firmware, 5, "tegra234-orin", edKey, rsaKey, []string{leafPEM, caPEM}, tsa)

	// Attempt verification for different board (e.g. tegra210-nano) -> must fail!
	err := fwsign.VerifyFirmwareReceipt(firmware, receipt, 1, "tegra210-nano", caCert, tsa.Cert)
	if err == nil {
		t.Fatal("expected verification to fail due to HW ID mismatch")
	}
	if !strings.Contains(err.Error(), "hardware compatibility ID mismatch") {
		t.Errorf("expected HW ID mismatch message, got: %v", err)
	}
}

func TestFirmwareTamperingDetection(t *testing.T) {
	firmware := []byte("ORIGINAL_AUTHENTIC_FIRMWARE")
	_, caCert, rsaKey, _, caPEM, leafPEM, _ := fwsign.GenerateCodeSigningCAAndLeaf(365)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	tsa, _ := fwsign.NewTsaAuthority()

	receipt, _ := fwsign.SignFirmware(firmware, 1, "board-alpha", edKey, rsaKey, []string{leafPEM, caPEM}, tsa)

	// 1. Bit flip in firmware payload
	tamperedFirmware := []byte("ORIGINAL_AUTHENTIC_FIRMWARF") // Last char changed 'E' -> 'F'
	err := fwsign.VerifyFirmwareReceipt(tamperedFirmware, receipt, 1, "board-alpha", caCert, tsa.Cert)
	if err == nil {
		t.Fatal("expected verification to fail on tampered firmware")
	}
	if !strings.Contains(err.Error(), "tampered") && !strings.Contains(err.Error(), "digest mismatch") {
		t.Errorf("expected tampered error, got: %v", err)
	}

	// 2. Size modification
	truncatedFirmware := firmware[:len(firmware)-1]
	err = fwsign.VerifyFirmwareReceipt(truncatedFirmware, receipt, 1, "board-alpha", caCert, tsa.Cert)
	if err == nil {
		t.Fatal("expected verification to fail on truncated firmware")
	}
}

func TestBinaryTrailerAttachAndExtract(t *testing.T) {
	firmware := []byte("PAYLOAD_FOR_TRAILER_TESTING_1234567890")
	_, _, rsaKey, _, caPEM, leafPEM, _ := fwsign.GenerateCodeSigningCAAndLeaf(365)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	tsa, _ := fwsign.NewTsaAuthority()

	receipt, _ := fwsign.SignFirmware(firmware, 10, "orin-jetson", edKey, rsaKey, []string{leafPEM, caPEM}, tsa)

	// Attach trailer
	firmwareWithTrailer, err := fwsign.AttachTrailer(firmware, receipt)
	if err != nil {
		t.Fatalf("attach trailer: %v", err)
	}
	if len(firmwareWithTrailer) <= len(firmware) {
		t.Fatal("firmwareWithTrailer should be larger than original firmware")
	}

	// Extract trailer
	extractedFirmware, extractedReceipt, err := fwsign.ExtractTrailer(firmwareWithTrailer)
	if err != nil {
		t.Fatalf("extract trailer: %v", err)
	}

	if string(extractedFirmware) != string(firmware) {
		t.Fatal("extracted firmware does not match original firmware")
	}
	if extractedReceipt.Header.SVN != 10 {
		t.Errorf("extracted SVN %d != 10", extractedReceipt.Header.SVN)
	}
	if extractedReceipt.Header.HardwareCompatID != "orin-jetson" {
		t.Errorf("extracted HW ID %s != orin-jetson", extractedReceipt.Header.HardwareCompatID)
	}
}

func TestLongTermTimestampedValidityInvariant(t *testing.T) {
	// Create CA and Leaf certificates
	_, caCert, leafKey, leafCert, _, _, err := fwsign.GenerateCodeSigningCAAndLeaf(365)
	if err != nil {
		t.Fatalf("generate certs: %v", err)
	}

	// Invariant 1: Valid timestamp inside [NotBefore, NotAfter] succeeds even if current time is far in future
	validTimestamp := leafCert.NotBefore.Add(24 * time.Hour)
	err = fwsign.VerifyCodeSigningCertChain(leafCert, caCert, validTimestamp)
	if err != nil {
		t.Fatalf("expected valid timestamp to succeed: %v", err)
	}

	// Invariant 2: Timestamp before NotBefore must fail
	tooEarlyTimestamp := leafCert.NotBefore.Add(-2 * time.Hour)
	err = fwsign.VerifyCodeSigningCertChain(leafCert, caCert, tooEarlyTimestamp)
	if err == nil {
		t.Fatal("expected timestamp before NotBefore to fail")
	}

	// Invariant 3: Timestamp after NotAfter must fail
	tooLateTimestamp := leafCert.NotAfter.Add(2 * time.Hour)
	err = fwsign.VerifyCodeSigningCertChain(leafCert, caCert, tooLateTimestamp)
	if err == nil {
		t.Fatal("expected timestamp after NotAfter to fail")
	}

	_ = leafKey
}

func TestCodeSigningEKUEnforced(t *testing.T) {
	// Create cert lacking ExtKeyUsageCodeSigning (e.g. only ServerAuth)
	caKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	caSerial, _ := rand.Int(rand.Reader, serialLimit)
	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 3072)
	leafSerial, _ := rand.Int(rand.Reader, serialLimit)
	badLeafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "Invalid Leaf"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, // Missing CodeSigning!
	}
	badLeafDER, _ := x509.CreateCertificate(rand.Reader, badLeafTemplate, caCert, &leafKey.PublicKey, caKey)
	badLeafCert, _ := x509.ParseCertificate(badLeafDER)

	err = fwsign.VerifyCodeSigningCertChain(badLeafCert, caCert, time.Now())
	if err == nil {
		t.Fatal("expected failure due to missing ExtKeyUsageCodeSigning")
	}
	if !strings.Contains(err.Error(), "missing ExtKeyUsageCodeSigning") {
		t.Errorf("expected missing EKU message, got: %v", err)
	}
}

// ----------------------------------------------------------------------------
// SUITE 2: PKCS#11 v3.0 HSM Session State Machine & RFC 3161 TSA Engine
// ----------------------------------------------------------------------------

func TestPkcs11SessionLifecycle(t *testing.T) {
	hsm := fwsign.NewHsmTokenSession("user123", "so123", 3)
	if hsm.State != fwsign.CKS_UNINITIALIZED {
		t.Errorf("initial state should be CKS_UNINITIALIZED, got %d", hsm.State)
	}

	rc := hsm.C_Initialize()
	if rc != fwsign.CKR_OK {
		t.Errorf("C_Initialize returned 0x%08X", rc)
	}

	sessID, rc := hsm.C_OpenSession()
	if rc != fwsign.CKR_OK || sessID == 0 {
		t.Errorf("C_OpenSession failed: ID=%d, RC=0x%08X", sessID, rc)
	}
	if hsm.State != fwsign.CKS_RO_PUBLIC_SESSION {
		t.Errorf("post-open state should be CKS_RO_PUBLIC_SESSION, got %d", hsm.State)
	}

	// Login with correct PIN
	rc = hsm.C_Login(fwsign.CKU_USER, "user123")
	if rc != fwsign.CKR_OK {
		t.Errorf("C_Login returned 0x%08X", rc)
	}
	if hsm.State != fwsign.CKS_RO_USER_FUNCTIONS {
		t.Errorf("post-login state should be CKS_RO_USER_FUNCTIONS, got %d", hsm.State)
	}

	// Logout
	rc = hsm.C_Logout()
	if rc != fwsign.CKR_OK {
		t.Errorf("C_Logout returned 0x%08X", rc)
	}
	if hsm.State != fwsign.CKS_RO_PUBLIC_SESSION {
		t.Errorf("post-logout state should be CKS_RO_PUBLIC_SESSION, got %d", hsm.State)
	}

	// Close session
	rc = hsm.C_CloseSession()
	if rc != fwsign.CKR_OK {
		t.Errorf("C_CloseSession returned 0x%08X", rc)
	}
	if hsm.State != fwsign.CKS_CLOSED {
		t.Errorf("post-close state should be CKS_CLOSED, got %d", hsm.State)
	}
}

func TestPkcs11SigningRequiresLogin(t *testing.T) {
	hsm := fwsign.NewHsmTokenSession("pin1", "sopin1", 3)
	hsm.C_Initialize()
	hsm.C_OpenSession()

	// Attempt to sign before logging in
	sig, rc := hsm.C_Sign([]byte("test_digest"))
	if rc != fwsign.CKR_USER_NOT_LOGGED_IN {
		t.Errorf("expected CKR_USER_NOT_LOGGED_IN (0x%08X), got 0x%08X", fwsign.CKR_USER_NOT_LOGGED_IN, rc)
	}
	if sig != nil {
		t.Error("signature should be nil on failed sign")
	}
}

func TestPkcs11KeySensitivityAndExtractabilityInvariants(t *testing.T) {
	hsm := fwsign.NewHsmTokenSession("pin1", "sopin1", 3)
	hsm.C_Initialize()
	hsm.C_OpenSession()
	hsm.C_Login(fwsign.CKU_USER, "pin1")

	// 1. Key with CKA_EXTRACTABLE == true (insecure!)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	hsm.AddKey(&fwsign.HsmKeyObject{
		ID:             "insecure-extractable-key",
		Label:          "Extractable Key",
		KeyType:        "ED25519",
		CkaSensitive:   true,
		CkaExtractable: true, // VIOLATION!
		CkaPrivate:     true,
		CkaSign:        true,
		Ed25519Key:     edKey,
	})

	rc := hsm.C_SignInit("insecure-extractable-key")
	if rc != fwsign.CKR_KEY_FUNCTION_NOT_PERMITTED {
		t.Errorf("expected CKR_KEY_FUNCTION_NOT_PERMITTED for extractable key, got 0x%08X", rc)
	}

	// 2. Key with CKA_SENSITIVE == false (insecure!)
	hsm.AddKey(&fwsign.HsmKeyObject{
		ID:             "insecure-non-sensitive-key",
		Label:          "Non-Sensitive Key",
		KeyType:        "ED25519",
		CkaSensitive:   false, // VIOLATION!
		CkaExtractable: false,
		CkaPrivate:     true,
		CkaSign:        true,
		Ed25519Key:     edKey,
	})

	rc = hsm.C_SignInit("insecure-non-sensitive-key")
	if rc != fwsign.CKR_KEY_FUNCTION_NOT_PERMITTED {
		t.Errorf("expected CKR_KEY_FUNCTION_NOT_PERMITTED for non-sensitive key, got 0x%08X", rc)
	}

	// 3. Proper key: CKA_SENSITIVE=true, CKA_EXTRACTABLE=false
	hsm.AddKey(&fwsign.HsmKeyObject{
		ID:             "hardened-hsm-key",
		Label:          "Hardened Key",
		KeyType:        "ED25519",
		CkaSensitive:   true,
		CkaExtractable: false,
		CkaPrivate:     true,
		CkaSign:        true,
		Ed25519Key:     edKey,
	})

	rc = hsm.C_SignInit("hardened-hsm-key")
	if rc != fwsign.CKR_OK {
		t.Errorf("expected CKR_OK for hardened key, got 0x%08X", rc)
	}

	sig, rc := hsm.C_Sign([]byte("data_to_sign_32_bytes_digest_000"))
	if rc != fwsign.CKR_OK || len(sig) != 64 {
		t.Errorf("C_Sign failed: RC=0x%08X, len=%d", rc, len(sig))
	}
}

func TestPkcs11PinLockoutMechanics(t *testing.T) {
	hsm := fwsign.NewHsmTokenSession("correct_pin", "so_pin", 3)
	hsm.C_Initialize()
	hsm.C_OpenSession()

	// Attempt 1: wrong PIN
	rc := hsm.C_Login(fwsign.CKU_USER, "wrong_pin")
	if rc != fwsign.CKR_PIN_INCORRECT {
		t.Errorf("expected CKR_PIN_INCORRECT, got 0x%08X", rc)
	}
	if hsm.PinRetries != 1 {
		t.Errorf("expected retries 1, got %d", hsm.PinRetries)
	}

	// Attempt 2: wrong PIN
	rc = hsm.C_Login(fwsign.CKU_USER, "wrong_pin")
	if rc != fwsign.CKR_PIN_INCORRECT {
		t.Errorf("expected CKR_PIN_INCORRECT, got 0x%08X", rc)
	}
	if hsm.PinRetries != 2 {
		t.Errorf("expected retries 2, got %d", hsm.PinRetries)
	}

	// Attempt 3: wrong PIN (threshold reached!)
	rc = hsm.C_Login(fwsign.CKU_USER, "wrong_pin")
	if rc != fwsign.CKR_PIN_LOCKED {
		t.Errorf("expected CKR_PIN_LOCKED on 3rd attempt, got 0x%08X", rc)
	}
	if !hsm.IsPinLocked {
		t.Error("HSM should be locked")
	}

	// Attempt with CORRECT PIN while locked -> must be rejected!
	rc = hsm.C_Login(fwsign.CKU_USER, "correct_pin")
	if rc != fwsign.CKR_PIN_LOCKED {
		t.Errorf("expected CKR_PIN_LOCKED even with correct PIN, got 0x%08X", rc)
	}

	// Administrative SO unlock
	rc = hsm.ResetPin("so_pin", "new_correct_pin")
	if rc != fwsign.CKR_OK {
		t.Errorf("ResetPin failed: 0x%08X", rc)
	}
	if hsm.IsPinLocked {
		t.Error("HSM should be unlocked after SO reset")
	}

	// Login with new PIN
	rc = hsm.C_Login(fwsign.CKU_USER, "new_correct_pin")
	if rc != fwsign.CKR_OK {
		t.Errorf("login with new PIN failed: 0x%08X", rc)
	}
}

func TestRfc3161TimestampTokenVerification(t *testing.T) {
	tsa, err := fwsign.NewTsaAuthority()
	if err != nil {
		t.Fatalf("new tsa: %v", err)
	}

	sig := []byte("SAMPLE_SIGNATURE_BYTES_1234567890")
	imgDigest := sha256.Sum256([]byte("FIRMWARE_BINARY"))
	nonce := []byte("16_BYTE_NONCE___")

	token, err := fwsign.GenerateTimestampToken(sig, imgDigest[:], nonce, tsa, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	// 1. Valid verification
	err = fwsign.VerifyTimestampToken(token, sig, imgDigest[:], tsa.Cert)
	if err != nil {
		t.Fatalf("verify valid token failed: %v", err)
	}

	// 2. Tampered signature
	badSig := []byte("SAMPLE_SIGNATURE_BYTES_123456789X")
	err = fwsign.VerifyTimestampToken(token, badSig, imgDigest[:], tsa.Cert)
	if err == nil {
		t.Fatal("expected failure on tampered signature")
	}

	// 3. Tampered image digest
	badDigest := sha256.Sum256([]byte("TAMPERED_FIRMWARE"))
	err = fwsign.VerifyTimestampToken(token, sig, badDigest[:], tsa.Cert)
	if err == nil {
		t.Fatal("expected failure on tampered image digest")
	}
}

// ----------------------------------------------------------------------------
// SUITE 3: 10-Rule Auditor & Posture Score Math (LH-FWS-001..010)
// ----------------------------------------------------------------------------

func findRepoRoot() string {
	paths := []string{
		".",
		"..",
		"../..",
	}
	for _, p := range paths {
		if _, err := os.Stat(filepath.Join(p, "go.mod")); err == nil {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}
	return "."
}

func findFixture(name string) string {
	paths := []string{
		filepath.Join("fixtures", name),
		filepath.Join("..", "fixtures", name),
		filepath.Join("..", "..", "fixtures", name),
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}
	return filepath.Join(findRepoRoot(), "fixtures", name)
}

func TestAuditorHardenedPolicy(t *testing.T) {
	policy, err := fwsign.ParsePolicyFile(findFixture("hardened_fwsign_policy.json"))
	if err != nil {
		t.Fatalf("parse hardened policy: %v", err)
	}

	report := fwsign.EvaluatePosture(policy)
	if report.TotalRules != 10 {
		t.Errorf("expected 10 rules, got %d", report.TotalRules)
	}
	if report.PassedRules != 10 {
		t.Errorf("expected 10 passed rules, got %d", report.PassedRules)
	}
	if report.FailedRules != 0 {
		t.Errorf("expected 0 failed rules, got %d", report.FailedRules)
	}
	if report.TotalDeductions != 0 {
		t.Errorf("expected 0 deductions, got %d", report.TotalDeductions)
	}
	if report.PostureScore != 100 {
		t.Errorf("expected posture score 100, got %d", report.PostureScore)
	}

	// Verify all individual findings are passed
	for _, f := range report.Findings {
		if !f.Passed {
			t.Errorf("rule %s failed in hardened policy", f.RuleID)
		}
	}
}

func TestAuditorVulnerablePolicy(t *testing.T) {
	policy, err := fwsign.ParsePolicyFile(findFixture("vulnerable_fwsign_policy.json"))
	if err != nil {
		t.Fatalf("parse vulnerable policy: %v", err)
	}

	report := fwsign.EvaluatePosture(policy)
	if report.TotalRules != 10 {
		t.Errorf("expected 10 rules, got %d", report.TotalRules)
	}
	if report.PassedRules != 0 {
		t.Errorf("expected 0 passed rules, got %d", report.PassedRules)
	}
	if report.FailedRules != 10 {
		t.Errorf("expected 10 failed rules, got %d", report.FailedRules)
	}

	// Total deductions = 25*3 + 10*4 + 4*2 + 1 = 124
	if report.TotalDeductions != 124 {
		t.Errorf("expected 124 total deductions, got %d", report.TotalDeductions)
	}
	if report.PostureScore != 0 {
		t.Errorf("expected posture score 0, got %d", report.PostureScore)
	}

	expectedRules := []struct {
		id  string
		ded int
		sev fwsign.Severity
	}{
		{"LH-FWS-001", 25, fwsign.SeverityCritical},
		{"LH-FWS-002", 25, fwsign.SeverityCritical},
		{"LH-FWS-003", 25, fwsign.SeverityCritical},
		{"LH-FWS-004", 10, fwsign.SeverityHigh},
		{"LH-FWS-005", 10, fwsign.SeverityHigh},
		{"LH-FWS-006", 10, fwsign.SeverityHigh},
		{"LH-FWS-007", 10, fwsign.SeverityHigh},
		{"LH-FWS-008", 4, fwsign.SeverityMedium},
		{"LH-FWS-009", 4, fwsign.SeverityMedium},
		{"LH-FWS-010", 1, fwsign.SeverityLow},
	}

	for i, exp := range expectedRules {
		f := report.Findings[i]
		if f.RuleID != exp.id {
			t.Errorf("finding %d: expected %s, got %s", i, exp.id, f.RuleID)
		}
		if f.Deduction != exp.ded {
			t.Errorf("rule %s: expected deduction %d, got %d", exp.id, exp.ded, f.Deduction)
		}
		if f.Severity != exp.sev {
			t.Errorf("rule %s: expected severity %s, got %s", exp.id, exp.sev, f.Severity)
		}
		if f.Passed {
			t.Errorf("rule %s should have failed in vulnerable policy", exp.id)
		}
	}
}

func TestAuditorSingleRuleTriggers(t *testing.T) {
	// Base: perfectly hardened policy
	base, err := fwsign.ParsePolicyFile(findFixture("hardened_fwsign_policy.json"))
	if err != nil {
		t.Fatalf("parse hardened policy: %v", err)
	}

	// Trigger Rule 1 (LH-FWS-001, -25)
	p1 := *base
	p1.AllowPkcs1v15Padding = true
	r1 := fwsign.EvaluatePosture(&p1)
	if r1.TotalDeductions != 25 || r1.PostureScore != 75 {
		t.Errorf("Rule 1 trigger: expected deduction 25 / score 75, got ded %d / score %d", r1.TotalDeductions, r1.PostureScore)
	}

	// Trigger Rule 4 (LH-FWS-004, -10)
	p4 := *base
	p4.BindSvnInSignature = false
	r4 := fwsign.EvaluatePosture(&p4)
	if r4.TotalDeductions != 10 || r4.PostureScore != 90 {
		t.Errorf("Rule 4 trigger: expected deduction 10 / score 90, got ded %d / score %d", r4.TotalDeductions, r4.PostureScore)
	}

	// Trigger Rule 8 (LH-FWS-008, -4)
	p8 := *base
	p8.HybridDualSignatureEnabled = false
	r8 := fwsign.EvaluatePosture(&p8)
	if r8.TotalDeductions != 4 || r8.PostureScore != 96 {
		t.Errorf("Rule 8 trigger: expected deduction 4 / score 96, got ded %d / score %d", r8.TotalDeductions, r8.PostureScore)
	}

	// Trigger Rule 10 (LH-FWS-010, -1)
	p10 := *base
	p10.TransparencyLogReceiptEnabled = false
	r10 := fwsign.EvaluatePosture(&p10)
	if r10.TotalDeductions != 1 || r10.PostureScore != 99 {
		t.Errorf("Rule 10 trigger: expected deduction 1 / score 99, got ded %d / score %d", r10.TotalDeductions, r10.PostureScore)
	}

	// Trigger Combo: Rule 1 (-25) + Rule 4 (-10) = -35 -> score 65
	pCombo := *base
	pCombo.AllowPkcs1v15Padding = true
	pCombo.BindSvnInSignature = false
	rCombo := fwsign.EvaluatePosture(&pCombo)
	if rCombo.TotalDeductions != 35 || rCombo.PostureScore != 65 {
		t.Errorf("Combo trigger: expected deduction 35 / score 65, got ded %d / score %d", rCombo.TotalDeductions, rCombo.PostureScore)
	}
}

// ----------------------------------------------------------------------------
// SUITE 4: Exporters & Serialization (Table, JSON, SARIF)
// ----------------------------------------------------------------------------

func TestExportersFormatting(t *testing.T) {
	policy, err := fwsign.ParsePolicyFile(findFixture("hardened_fwsign_policy.json"))
	if err != nil {
		t.Fatalf("parse hardened policy: %v", err)
	}
	report := fwsign.EvaluatePosture(policy)

	// 1. Table
	tbl := fwsign.FormatTable(report)
	if !strings.Contains(tbl, "LH-FWS-001") || !strings.Contains(tbl, "POSTURE SCORE: 100 / 100") {
		t.Errorf("table output missing expected strings: %s", tbl)
	}

	// 2. JSON
	jsStr, err := fwsign.FormatJSON(report)
	if err != nil {
		t.Fatalf("format json: %v", err)
	}
	var roundtrip fwsign.AuditReport
	if err := json.Unmarshal([]byte(jsStr), &roundtrip); err != nil {
		t.Fatalf("unmarshal roundtrip json: %v", err)
	}
	if roundtrip.PostureScore != 100 {
		t.Errorf("expected roundtrip score 100, got %d", roundtrip.PostureScore)
	}

	// 3. SARIF v2.1.0
	sarifStr, err := fwsign.FormatSARIF(report)
	if err != nil {
		t.Fatalf("format sarif: %v", err)
	}
	if !strings.Contains(sarifStr, "sarif-schema-2.1.0.json") {
		t.Error("SARIF output missing schema URI")
	}
	if !strings.Contains(sarifStr, "lh-fw-sign") {
		t.Error("SARIF output missing driver name")
	}
}

func TestSarifWithViolations(t *testing.T) {
	vulnPolicy, err := fwsign.ParsePolicyFile(findFixture("vulnerable_fwsign_policy.json"))
	if err != nil {
		t.Fatalf("parse vulnerable policy: %v", err)
	}
	vulnReport := fwsign.EvaluatePosture(vulnPolicy)

	sarifStr, err := fwsign.FormatSARIF(vulnReport)
	if err != nil {
		t.Fatalf("format sarif: %v", err)
	}

	var doc fwsign.SarifReport
	if err := json.Unmarshal([]byte(sarifStr), &doc); err != nil {
		t.Fatalf("unmarshal sarif: %v", err)
	}
	if len(doc.Runs) == 0 {
		t.Fatal("sarif has no runs")
	}
	if len(doc.Runs[0].Results) != 10 {
		t.Errorf("expected 10 sarif results for vulnerable report, got %d", len(doc.Runs[0].Results))
	}
}

// ----------------------------------------------------------------------------
// SUITE 5: Subprocess CLI Execution & Exit Codes
// ----------------------------------------------------------------------------

func TestCliSubprocessInvocations(t *testing.T) {
	// Build binary into temporary directory
	tmpDir, err := os.MkdirTemp("", "fwsign_test_*")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	binPath := filepath.Join(tmpDir, "lh-fw-sign")
	root := findRepoRoot()
	goBin := "go"
	if _, err := exec.LookPath("go"); err != nil {
		if _, err := os.Stat("/tmp/go/bin/go"); err == nil {
			goBin = "/tmp/go/bin/go"
		}
	}
	buildCmd := exec.Command(goBin, "build", "-o", binPath, filepath.Join(root, "cmd", "lh-fw-sign"))
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build binary failed: %v, out: %s", err, string(out))
	}

	// Test 1: --version (exit 0)
	cmdVer := exec.Command(binPath, "--version")
	outVer, err := cmdVer.CombinedOutput()
	if err != nil {
		t.Fatalf("--version failed: %v, out: %s", err, string(outVer))
	}
	if !strings.Contains(string(outVer), "lh-fw-sign 0.1.0") {
		t.Errorf("version output unexpected: %s", string(outVer))
	}

	// Test 2: --help (exit 0)
	cmdHelp := exec.Command(binPath, "--help")
	outHelp, err := cmdHelp.CombinedOutput()
	if err != nil {
		t.Fatalf("--help failed: %v, out: %s", err, string(outHelp))
	}
	if !strings.Contains(string(outHelp), "Usage:") {
		t.Errorf("help output unexpected: %s", string(outHelp))
	}

	// Test 3: scan hardened policy (exit 0)
	cmdScanHard := exec.Command(binPath, "scan", findFixture("hardened_fwsign_policy.json"), "--format", "table")
	outScanHard, err := cmdScanHard.CombinedOutput()
	if err != nil {
		t.Fatalf("scan hardened failed: %v, out: %s", err, string(outScanHard))
	}
	if !strings.Contains(string(outScanHard), "POSTURE SCORE: 100 / 100 [PASS]") {
		t.Errorf("scan hardened unexpected output: %s", string(outScanHard))
	}

	// Test 4: scan vulnerable policy (exit 1)
	cmdScanVuln := exec.Command(binPath, "scan", findFixture("vulnerable_fwsign_policy.json"), "--format", "json")
	outScanVuln, err := cmdScanVuln.CombinedOutput()
	if err == nil {
		t.Fatal("expected scan vulnerable to exit with code 1, but exited 0")
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 1 {
			t.Errorf("expected exit code 1, got %d", exitErr.ExitCode())
		}
	} else {
		t.Fatalf("unexpected error type: %v", err)
	}
	if !strings.Contains(string(outScanVuln), `"posture_score": 0`) {
		t.Errorf("expected score 0 in JSON output: %s", string(outScanVuln))
	}

	// Test 5: inspect-hsm (exit 0)
	cmdHsm := exec.Command(binPath, "inspect-hsm", "--simulate-pin-lockout")
	outHsm, err := cmdHsm.CombinedOutput()
	if err != nil {
		t.Fatalf("inspect-hsm failed: %v, out: %s", err, string(outHsm))
	}
	if !strings.Contains(string(outHsm), "CKR_PIN_LOCKED") {
		t.Errorf("inspect-hsm missing lockout text: %s", string(outHsm))
	}

	// Test 6: verify valid fixture (exit 0)
	cmdVerify := exec.Command(binPath, "verify",
		"--firmware", findFixture("sample_bootloader.bin"),
		"--receipt", findFixture("sample_signed_receipt.json"),
		"--min-svn", "7",
		"--hw-id", "tegra234-orin-industrial",
	)
	outVerify, err := cmdVerify.CombinedOutput()
	if err != nil {
		t.Fatalf("verify fixture failed: %v, out: %s", err, string(outVerify))
	}
	if !strings.Contains(string(outVerify), "VERIFIED AUTHENTIC & UNTAMPERED") {
		t.Errorf("verify fixture unexpected output: %s", string(outVerify))
	}

	// Test 7: verify with anti-rollback failure (SVN 8 > signed 7) -> exit 1
	cmdRollback := exec.Command(binPath, "verify",
		"--firmware", findFixture("sample_bootloader.bin"),
		"--receipt", findFixture("sample_signed_receipt.json"),
		"--min-svn", "8", // HIGHER than signed 7!
	)
	outRollback, err := cmdRollback.CombinedOutput()
	if err == nil {
		t.Fatal("expected anti-rollback check to exit 1, got exit 0")
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 1 {
			t.Errorf("expected exit code 1, got %d", exitErr.ExitCode())
		}
	}
	if !strings.Contains(string(outRollback), "anti-rollback check failed") {
		t.Errorf("expected rollback error message, got: %s", string(outRollback))
	}

	// Test 8: invalid command arguments -> exit 2
	cmdInvalid := exec.Command(binPath, "nonexistent-command")
	_, err = cmdInvalid.CombinedOutput()
	if err == nil {
		t.Fatal("expected unknown subcommand to exit 2, got exit 0")
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 2 {
			t.Errorf("expected exit code 2, got %d", exitErr.ExitCode())
		}
	}
}
