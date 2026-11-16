# Changelog

All notable changes to **`lh-firmware-sign-cli`** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-13

### Added
- **Hybrid Ed25519 + RSA-PSS Binary Signer**:
  - Authenticated firmware metadata envelope (`FirmwareHeaderV1`) binding magic `"LHFWSIG1"`, monotonic SVN, hardware compatibility ID, image size, SHA-256, and SHA-384.
  - RFC 8032 Ed25519 primary digital signature generation and verification.
  - RFC 8017 RSASSA-PSS-SHA384 secondary signature generation enforcing salt length equal to hash length (`s_len = h_len = 48 bytes`).
  - Binary firmware trailer serialization and parsing (`LHFWSIG1`).
- **X.509 v3 Code-Signing Certificate Chain & Long-Term TSA Invariant**:
  - CA and leaf code-signing certificate generation with `ExtKeyUsageCodeSigning` and `KeyUsageDigitalSignature`.
  - Signature chain verification with long-term timestamped validity invariant ($T_{\text{notBefore}} \le T_{\text{TSA}} \le T_{\text{notAfter}}$).
- **PKCS#11 v3.0 HSM Session State Machine**:
  - Full lifecycle modeling (`CKS_UNINITIALIZED` -> `CKS_RO_PUBLIC_SESSION` -> `CKS_RO_USER_FUNCTIONS` -> `CKS_CLOSED`).
  - Invariant enforcement for `CKA_SENSITIVE = true` and `CKA_EXTRACTABLE = false`.
  - Automatic latching of `CKR_PIN_LOCKED` upon reaching maximum PIN retry threshold.
- **RFC 3161 Time-Stamp Authority (TSA) Engine**:
  - Message imprint calculation with 128-bit CSPRNG nonce binding.
  - Timestamp token generation and constant-time cryptographic verification.
- **10-Rule Firmware Signing Security Posture Auditor (`auditor.go`)**:
  - Normative evaluation of rules `LH-FWS-001` through `LH-FWS-010`.
  - Standardized Logihertz security posture score calculation ($S_{\text{posture}} \in [0, 100]$).
- **Exporting & CLI**:
  - ANSI Table, Canonical JSON, and OASIS SARIF v2.1.0 reporting.
  - CLI commands: `scan`, `sign`, `verify`, `inspect-hsm`, `gen-cert`, `--version`, and `--help`.
- **Zero External Dependencies**:
  - Pure Go Standard Library implementation with zero `require` blocks in `go.mod`.
