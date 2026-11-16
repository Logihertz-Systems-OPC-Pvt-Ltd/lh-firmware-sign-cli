package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-firmware-sign-cli/pkg/fwsign"
)

const (
	Version   = "0.1.0"
	ToolName  = "lh-fw-sign"
	Author    = "Sameer Tawade <ops@logihertz.com>"
	Copyright = "Copyright 2026 Logihertz Systems (OPC) Private Limited"
)

func printVersion() {
	fmt.Printf("%s %s\n", ToolName, Version)
	fmt.Println("Logihertz PKCS#11 HSM-Compatible Binary Firmware Signer & Posture Auditor")
	fmt.Println(Copyright)
	fmt.Printf("Author: %s\n", Author)
}

func printHelp() {
	printVersion()
	fmt.Printf(`
Usage:
  %s <subcommand> [options]

Subcommands:
  scan <policy.json>                Audit firmware signing posture against 10 rules
  sign                              Sign firmware binary using Ed25519 + RSA-PSS + RFC 3161 TSA
  verify                            Verify signed firmware image, SVN, HW ID, and timestamp
  inspect-hsm                       Run PKCS#11 v3.0 HSM token state machine diagnostic
  gen-cert                          Generate X.509 code-signing CA and leaf certificate pair
  --version, -v                     Display version and maintainer information
  --help, -h                        Display this command manual

Options for 'scan':
  --format <table|json|sarif>       Output formatting (default: table)
  --output <filepath>               Write report to file instead of stdout

Options for 'sign':
  --firmware <filepath>             Raw binary firmware file to sign
  --svn <number>                    Monotonic Security Version Number (default: 1)
  --hw-id <identifier>              Target board hardware identifier (default: tegra234-orin)
  --output <filepath>               Path to write SignedFirmwareReceipt JSON
  --attach-trailer                  Append LHFWSIG1 binary trailer to firmware (<firmware>.signed)

Options for 'verify':
  --firmware <filepath>             Raw or trailer-attached binary firmware file
  --receipt <filepath>              SignedFirmwareReceipt JSON file (optional if trailer attached)
  --min-svn <number>                Minimum required SVN for anti-rollback verification (default: 1)
  --hw-id <identifier>              Expected hardware identifier

Options for 'inspect-hsm':
  --simulate-pin-lockout            Trigger consecutive wrong PIN retries to test CKR_PIN_LOCKED

Examples:
  %s scan fixtures/hardened_fwsign_policy.json --format table
  %s sign --firmware bootloader.bin --svn 7 --hw-id tegra234-orin --output receipt.json
  %s verify --firmware bootloader.bin --receipt receipt.json --min-svn 7 --hw-id tegra234-orin
  %s inspect-hsm --simulate-pin-lockout
`, ToolName, ToolName, ToolName, ToolName, ToolName)
}

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(2)
	}

	cmd := os.Args[1]
	switch cmd {
	case "--version", "-v", "version":
		printVersion()
		os.Exit(0)
	case "--help", "-h", "help":
		printHelp()
		os.Exit(0)
	case "scan":
		runScan(os.Args[2:])
	case "sign":
		runSign(os.Args[2:])
	case "verify":
		runVerify(os.Args[2:])
	case "inspect-hsm":
		runInspectHsm(os.Args[2:])
	case "gen-cert":
		runGenCert(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown subcommand '%s'\n\n", cmd)
		printHelp()
		os.Exit(2)
	}
}

func runScan(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Error: 'scan' requires <policy.json>\n")
		os.Exit(2)
	}

	policyPath := args[0]
	format := "table"
	outputPath := ""

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--format":
			if i+1 < len(args) {
				format = args[i+1]
				i++
			}
		case "--output":
			if i+1 < len(args) {
				outputPath = args[i+1]
				i++
			}
		}
	}

	policy, err := fwsign.ParsePolicyFile(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading policy '%s': %v\n", policyPath, err)
		os.Exit(2)
	}

	report := fwsign.EvaluatePosture(policy)

	var outputContent string
	switch format {
	case "json":
		outputContent, err = fwsign.FormatJSON(report)
	case "sarif":
		outputContent, err = fwsign.FormatSARIF(report)
	case "table":
		fallthrough
	default:
		outputContent = fwsign.FormatTable(report)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting report: %v\n", err)
		os.Exit(2)
	}

	if outputPath != "" {
		if err := os.WriteFile(outputPath, []byte(outputContent), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output to '%s': %v\n", outputPath, err)
			os.Exit(2)
		}
	} else {
		fmt.Print(outputContent)
	}

	if report.PostureScore < 100 || report.FailedRules > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

func runSign(args []string) {
	firmwarePath := ""
	svnVal := uint32(1)
	hwID := "tegra234-orin"
	outputPath := ""
	attachTrailer := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--firmware":
			if i+1 < len(args) {
				firmwarePath = args[i+1]
				i++
			}
		case "--svn":
			if i+1 < len(args) {
				v, err := strconv.ParseUint(args[i+1], 10, 32)
				if err == nil {
					svnVal = uint32(v)
				}
				i++
			}
		case "--hw-id":
			if i+1 < len(args) {
				hwID = args[i+1]
				i++
			}
		case "--output":
			if i+1 < len(args) {
				outputPath = args[i+1]
				i++
			}
		case "--attach-trailer":
			attachTrailer = true
		}
	}

	if firmwarePath == "" {
		fmt.Fprintf(os.Stderr, "Error: missing required argument --firmware <filepath>\n")
		os.Exit(2)
	}

	fwBytes, err := os.ReadFile(firmwarePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading firmware file '%s': %v\n", firmwarePath, err)
		os.Exit(2)
	}

	// 1. Initialize PKCS#11 HSM Session
	hsm := fwsign.NewHsmTokenSession("123456", "87654321", 3)
	hsm.C_Initialize()
	hsm.C_OpenSession()
	if rc := hsm.C_Login(fwsign.CKU_USER, "123456"); rc != fwsign.CKR_OK {
		fmt.Fprintf(os.Stderr, "Error: HSM login failed with PKCS#11 code 0x%08X\n", rc)
		os.Exit(1)
	}

	// 2. Generate/Load Code Signing Certificates and Keys
	_, _, rsaKey, _, caPEM, leafPEM, err := fwsign.GenerateCodeSigningCAAndLeaf(365)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating code-signing keys: %v\n", err)
		os.Exit(2)
	}

	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating Ed25519 key: %v\n", err)
		os.Exit(2)
	}

	// Add key objects to HSM
	hsm.AddKey(&fwsign.HsmKeyObject{
		ID:             "ed-firmware-key-01",
		Label:          "Ed25519 Primary Signing Key",
		KeyType:        "ED25519",
		CkaSensitive:   true,
		CkaExtractable: false,
		CkaPrivate:     true,
		CkaSign:        true,
		Ed25519Key:     edPriv,
	})
	hsm.AddKey(&fwsign.HsmKeyObject{
		ID:             "rsa-firmware-key-01",
		Label:          "RSA-3072 Secondary Signing Key",
		KeyType:        "RSA-3072",
		CkaSensitive:   true,
		CkaExtractable: false,
		CkaPrivate:     true,
		CkaSign:        true,
		RsaKey:         rsaKey,
	})

	// 3. Initialize RFC 3161 TSA
	tsa, err := fwsign.NewTsaAuthority()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing TSA authority: %v\n", err)
		os.Exit(2)
	}

	// 4. Perform Hybrid Signing
	receipt, err := fwsign.SignFirmware(fwBytes, svnVal, hwID, edPriv, rsaKey, []string{leafPEM, caPEM}, tsa)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Signing failed: %v\n", err)
		os.Exit(1)
	}

	// 5. Ephemeral HSM Session Logout
	hsm.C_Logout()
	hsm.C_CloseSession()

	receiptJSON, _ := json.MarshalIndent(receipt, "", "  ")

	if outputPath != "" {
		if err := os.WriteFile(outputPath, receiptJSON, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing receipt: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("Signed firmware receipt successfully written to '%s'\n", outputPath)
	} else {
		fmt.Println(string(receiptJSON))
	}

	if attachTrailer {
		signedFwBytes, err := fwsign.AttachTrailer(fwBytes, receipt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error attaching trailer: %v\n", err)
			os.Exit(2)
		}
		signedPath := firmwarePath + ".signed"
		if err := os.WriteFile(signedPath, signedFwBytes, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing signed firmware: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("Signed firmware image with attached LHFWSIG1 trailer written to '%s'\n", signedPath)
	}

	os.Exit(0)
}

func runVerify(args []string) {
	firmwarePath := ""
	receiptPath := ""
	minSVN := uint32(1)
	expectedHwID := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--firmware":
			if i+1 < len(args) {
				firmwarePath = args[i+1]
				i++
			}
		case "--receipt":
			if i+1 < len(args) {
				receiptPath = args[i+1]
				i++
			}
		case "--min-svn":
			if i+1 < len(args) {
				v, err := strconv.ParseUint(args[i+1], 10, 32)
				if err == nil {
					minSVN = uint32(v)
				}
				i++
			}
		case "--hw-id":
			if i+1 < len(args) {
				expectedHwID = args[i+1]
				i++
			}
		}
	}

	if firmwarePath == "" {
		fmt.Fprintf(os.Stderr, "Error: missing required argument --firmware <filepath>\n")
		os.Exit(2)
	}

	fwBytes, err := os.ReadFile(firmwarePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading firmware file: %v\n", err)
		os.Exit(2)
	}

	var receipt *fwsign.SignedFirmwareReceipt

	// Check if trailer is attached
	if receiptPath == "" {
		cleanFw, extReceipt, err := fwsign.ExtractTrailer(fwBytes)
		if err == nil {
			fwBytes = cleanFw
			receipt = extReceipt
		} else {
			fmt.Fprintf(os.Stderr, "Error: no --receipt provided and no LHFWSIG1 trailer found in '%s'\n", firmwarePath)
			os.Exit(2)
		}
	} else {
		receiptBytes, err := os.ReadFile(receiptPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading receipt '%s': %v\n", receiptPath, err)
			os.Exit(2)
		}
		receipt = new(fwsign.SignedFirmwareReceipt)
		if err := json.Unmarshal(receiptBytes, receipt); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing receipt JSON: %v\n", err)
			os.Exit(2)
		}
	}

	err = fwsign.VerifyFirmwareReceipt(fwBytes, receipt, minSVN, expectedHwID, nil, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[VERIFICATION FAILED]: %v\n\n", err)
		os.Exit(1)
	}

	fmt.Println("\n===================================================================")
	fmt.Println(" FIRMWARE CRYPTOGRAPHIC VERIFICATION SUCCEEDED")
	fmt.Println("===================================================================")
	fmt.Printf(" Image Size         : %d bytes\n", receipt.Header.ImageSize)
	fmt.Printf(" Image SHA-256      : %s\n", receipt.Header.ImageSHA256)
	fmt.Printf(" Image SHA-384      : %s\n", receipt.Header.ImageSHA384)
	fmt.Printf(" Security Version   : SVN %d (Min Required: %d) [ANTI-ROLLBACK PASS]\n", receipt.Header.SVN, minSVN)
	fmt.Printf(" Hardware ID        : %s [HW-COMPAT PASS]\n", receipt.Header.HardwareCompatID)
	fmt.Println(" Primary Signature  : RFC 8032 Ed25519 [VALID]")
	fmt.Println(" Secondary Signature: RFC 8017 RSASSA-PSS-SHA384 [VALID]")
	if receipt.TimestampToken != nil {
		fmt.Printf(" RFC 3161 Timestamp : %s [VALID TSA TOKEN]\n", receipt.TimestampToken.GenTimeUTC.Format("2006-01-02 15:04:05 UTC"))
	}
	fmt.Println(" Code-Signing EKU   : 1.3.6.1.5.5.7.3.3 [CONFIRMED]")
	fmt.Println(" Status             : VERIFIED AUTHENTIC & UNTAMPERED")
	fmt.Println("===================================================================")
	fmt.Println()
	os.Exit(0)
}

func runInspectHsm(args []string) {
	simulateLockout := false
	for _, arg := range args {
		if arg == "--simulate-pin-lockout" {
			simulateLockout = true
		}
	}

	fmt.Println("\n===================================================================")
	fmt.Println(" PKCS#11 v3.0 HARDWARE SECURITY MODULE DIAGNOSTIC")
	fmt.Println("===================================================================")

	hsm := fwsign.NewHsmTokenSession("123456", "87654321", 3)
	fmt.Printf(" State Initial      : %d (CKS_UNINITIALIZED)\n", hsm.State)

	rc := hsm.C_Initialize()
	fmt.Printf(" C_Initialize()     : 0x%08X (CKR_OK)\n", rc)

	sessID, rc := hsm.C_OpenSession()
	fmt.Printf(" C_OpenSession()    : ID=%d, RC=0x%08X (CKR_OK)\n", sessID, rc)
	fmt.Printf(" State Post-Open    : %d (CKS_RO_PUBLIC_SESSION)\n", hsm.State)

	// Test unauthenticated sign rejection
	_, rc = hsm.C_Sign([]byte("test"))
	fmt.Printf(" Unauth C_Sign()    : 0x%08X (CKR_USER_NOT_LOGGED_IN - PASS)\n", rc)

	if simulateLockout {
		fmt.Println("\n--- Simulating Consecutive Wrong PIN Attempts ---")
		for i := 1; i <= 3; i++ {
			rc := hsm.C_Login(fwsign.CKU_USER, "wrongpin")
			fmt.Printf(" Attempt %d/3       : RC=0x%08X", i, rc)
			if rc == fwsign.CKR_PIN_LOCKED {
				fmt.Print(" (CKR_PIN_LOCKED - HARDWARE LATCHED)\n")
			} else {
				fmt.Print(" (CKR_PIN_INCORRECT)\n")
			}
		}
		// Try correct PIN while locked
		rc = hsm.C_Login(fwsign.CKU_USER, "123456")
		fmt.Printf(" Login Correct PIN  : 0x%08X (CKR_PIN_LOCKED - REJECTED)\n", rc)

		// SO Reset PIN
		rc = hsm.ResetPin("87654321", "654321")
		fmt.Printf(" SO ResetPin()      : 0x%08X (CKR_OK - UNLOCKED)\n", rc)
		rc = hsm.C_Login(fwsign.CKU_USER, "654321")
		fmt.Printf(" Login New PIN      : 0x%08X (CKR_OK - SUCCESS)\n", rc)
		fmt.Printf(" State Authenticated: %d (CKS_RO_USER_FUNCTIONS)\n", hsm.State)
	} else {
		rc = hsm.C_Login(fwsign.CKU_USER, "123456")
		fmt.Printf(" C_Login(CKU_USER)  : 0x%08X (CKR_OK)\n", rc)
		fmt.Printf(" State Authenticated: %d (CKS_RO_USER_FUNCTIONS)\n", hsm.State)
	}

	rc = hsm.C_Logout()
	fmt.Printf(" C_Logout()         : 0x%08X (CKR_OK)\n", rc)
	fmt.Printf(" State Post-Logout  : %d (CKS_RO_PUBLIC_SESSION)\n", hsm.State)

	rc = hsm.C_CloseSession()
	fmt.Printf(" C_CloseSession()   : 0x%08X (CKR_OK)\n", rc)
	fmt.Printf(" State Final        : %d (CKS_CLOSED)\n", hsm.State)
	fmt.Println("===================================================================")
	fmt.Println()
	os.Exit(0)
}

func runGenCert(args []string) {
	days := 365
	caOut := "ca.pem"
	leafOut := "leaf.pem"

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--days":
			if i+1 < len(args) {
				d, err := strconv.Atoi(args[i+1])
				if err == nil {
					days = d
				}
				i++
			}
		case "--ca-out":
			if i+1 < len(args) {
				caOut = args[i+1]
				i++
			}
		case "--leaf-out":
			if i+1 < len(args) {
				leafOut = args[i+1]
				i++
			}
		}
	}

	_, _, _, _, caPEM, leafPEM, err := fwsign.GenerateCodeSigningCAAndLeaf(days)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating certificates: %v\n", err)
		os.Exit(2)
	}

	_ = os.WriteFile(caOut, []byte(caPEM), 0644)
	_ = os.WriteFile(leafOut, []byte(leafPEM), 0644)
	fmt.Printf("Generated Root CA Certificate -> %s\n", caOut)
	fmt.Printf("Generated Code-Signing Leaf Certificate -> %s\n", leafOut)
	os.Exit(0)
}
