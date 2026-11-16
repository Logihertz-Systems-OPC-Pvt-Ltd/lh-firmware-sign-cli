# lh-firmware-sign-cli

**Production-Grade, Zero-Dependency Go PKCS#11 HSM-Compatible Binary Firmware Signer, Ed25519 & RSA-PSS Hybrid Signature Engine, RFC 3161 Timestamped X.509 Certificate Verifier, and 10-Rule Firmware Signing Security Posture Auditor.**

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-firmware-sign-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-firmware-sign-cli/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Language](https://img.shields.io/badge/Language-Go%201.22-00ADD8.svg?logo=go)](go.mod)
[![Zero External Dependencies](https://img.shields.io/badge/Dependencies-0%20(Pure%20Go%20Stdlib)-success.svg)](go.mod)

---

## 1. Executive Summary & Domain Scope

Securing embedded firmware across mission-critical systems, automotive ECUs, industrial automation controllers, and sovereign edge AI accelerators requires cryptographic integrity and non-repudiation. Vulnerabilities in firmware release workflows—such as single-operator key leakage, reliance on legacy algorithms, lack of anti-rollback counters, or untimestamped certificates—expose devices to persistent rootkits, malicious flashing, and supply chain tampering.

`lh-firmware-sign-cli` (`lh-fw-sign`) delivers an enterprise-grade, standalone cryptographic firmware signing and auditing CLI built with **100% pure Go standard library** (zero external dependencies):
- **Hybrid Dual Signatures**: Combines modern RFC 8032 Ed25519 with classical RFC 8017 RSASSA-PSS-SHA384 (enforcing salt length equal to hash length) to eliminate single-algorithm cryptographic vulnerabilities.
- **Authenticated Metadata Envelope (`FirmwareHeaderV1`)**: Binds monotonic Security Version Numbers (`SVN >= 1`) for hardware anti-rollback enforcement, canonical `HardwareCompatID` to prevent cross-board flashing, image sizes, and SHA-256 / SHA-384 dual digests.
- **Binary Trailer Engine (`LHFWSIG1`)**: Provides self-contained firmware trailer serialization and parsing, enabling monolithic `.bin.signed` images for bootloaders that read trailing cryptographic metadata.
- **PKCS#11 v3.0 HSM State Machine**: Models OASIS PKCS#11 session lifecycles (`CKS_UNINITIALIZED` $\to$ `CKS_RO_PUBLIC_SESSION` $\to$ `CKS_RO_USER_FUNCTIONS` $\to$ `CKS_CLOSED`), enforcing hardware `CKA_SENSITIVE = true`, `CKA_EXTRACTABLE = false`, and automatic `CKR_PIN_LOCKED` brute-force defenses.
- **RFC 3161 Cryptographic Time-Stamp Authority (TSA)**: Mints and validates independent cryptographic timestamp tokens binding CSPRNG nonces, dual signatures, and image digests to guarantee long-term certificate validity even after certificate expiration.
- **10-Rule Firmware Signing Posture Auditor**: Audits release infrastructure against normative industry standards (`LH-FWS-001` through `LH-FWS-010`), providing ANSI table, JSON, and OASIS SARIF v2.1.0 reporting.

---

## 2. Cryptographic Architecture

```
+-----------------------------------------------------------------------------------------+
|                                Raw Firmware Image (F)                                   |
|                          Size: |F| bytes | SHA-256 | SHA-384                            |
+-----------------------------------------------------------------------------------------+
                                             │
                                             ▼
+-----------------------------------------------------------------------------------------+
|                    Authenticated Metadata Envelope (FirmwareHeaderV1)                   |
|  - Magic: "LHFWSIG1"                 - FormatVersion: 1                                 |
|  - SVN: Monotonic Counter (>= 1)     - HardwareCompatID: Target Board String            |
|  - ImageSize: |F| bytes              - ImageSHA256 (32B) & ImageSHA384 (48B)            |
+-----------------------------------------------------------------------------------------+
                                             │
                                             ▼
+-----------------------------------------------------------------------------------------+
|                           Canonical Signing Pre-Image (M_sign)                          |
|    M_sign = SHA-384("LH_FW_SIGN_V1:" || CanonicalHeader || ImageSHA256 || ImageSHA384)  |
+-----------------------------------------------------------------------------------------+
                     │                                                     │
                     ▼ (Primary Algorithm)                                 ▼ (Secondary Algorithm)
+---------------------------------------+             +-----------------------------------+
|          RFC 8032 Ed25519             |             |        RFC 8017 RSASSA-PSS        |
|  - 256-bit Twisted Edwards Curve      |             |  - RSA-3072 / RSA-4096 Key        |
|  - Pure Ed25519 Deterministic Sig     |             |  - SHA-384 Digest                 |
|  - Sig Length: 64 bytes               |             |  - Salt Length == 48 bytes (Hash) |
+---------------------------------------+             +-----------------------------------+
                     │                                                     │
                     └──────────────────────┬──────────────────────────────┘
                                            ▼
+-----------------------------------------------------------------------------------------+
|                 PKCS#11 v3.0 Hardware Security Module (HSM) Session                     |
|  - CKA_SENSITIVE = true  | CKA_EXTRACTABLE = false | CKA_SIGN = true                    |
|  - C_Login(CKU_USER) Authenticated Session | Automatic C_Logout() Post-Operation        |
+-----------------------------------------------------------------------------------------+
                                            │
                                            ▼
+-----------------------------------------------------------------------------------------+
|                      RFC 3161 Cryptographic Time-Stamp Authority                        |
|  - Nonce: 128-bit CSPRNG                                                                |
|  - Imprint: SHA-256("LH_RFC3161_IMPRINT:" || Sig_Ed25519 || Sig_RSA || SHA-256(F) || N) |
|  - TimeStampToken: GenTimeUTC, SerialNumber, PolicyOID, TsaCertPEM                      |
+-----------------------------------------------------------------------------------------+
                                            │
                                            ▼
+-----------------------------------------------------------------------------------------+
|                                Signed Output Deliverables                               |
|  1. SignedFirmwareReceipt (Canonical JSON Receipt)                                      |
|  2. Monolithic Binary Image: [Firmware Payload (F)] || [LHFWSIG1 Binary Trailer]        |
+-----------------------------------------------------------------------------------------+
```

---

## 3. Mathematical Foundations & Security Invariants

### 3.1 Pre-Image Construction
Before digital signatures are calculated, all contextual parameters are encapsulated into a canonical byte sequence:

$$M_{\text{sign}} = \text{SHA-384}\left(\texttt{"LH\_FW\_SIGN\_V1:"} \parallel \text{CanonicalBytes}(\text{Header}) \parallel D_{\text{SHA256}} \parallel D_{\text{SHA384}}\right)$$

Where:
- $\text{CanonicalBytes}(\text{Header})$ encodes `"LHFWSIG1"`, `FormatVersion` ($4\text{B}$), `SVN` ($4\text{B}$), `len(HW_ID)` ($4\text{B}$), `HW_ID`, `ImageSize` ($8\text{B}$), `rawSHA256` ($32\text{B}$), and `rawSHA384` ($48\text{B}$).
- Binds monotonic anti-rollback state and target board identity directly into the signature domain.

### 3.2 Dual Signature Algorithms
1. **RFC 8032 Ed25519**:
   $$\sigma_{\text{Ed25519}} = \text{Ed25519.Sign}\left(SK_{\text{Ed25519}}, \; M_{\text{sign}}\right)$$
2. **RFC 8017 RSASSA-PSS with SHA-384**:
   Enforces salt length equal to hash length ($s_{\text{len}} = h_{\text{len}} = 48\text{ bytes}$):
   $$\sigma_{\text{RSA-PSS}} = \text{RSA.SignPSS}\left(SK_{\text{RSA}}, \; \text{SHA-384}, \; M_{\text{sign}}, \; \{s_{\text{len}} = 48\}\right)$$

### 3.3 RFC 3161 Time-Stamp Authority Imprint
$$\sigma_{\text{combined}} = \sigma_{\text{Ed25519}} \parallel \sigma_{\text{RSA-PSS}}$$

$$I_{\text{tsa}} = \text{SHA-256}\left(\texttt{"LH\_RFC3161\_IMPRINT:"} \parallel \sigma_{\text{combined}} \parallel D_{\text{SHA256}} \parallel N_{\text{tsa}}\right)$$

Where $N_{\text{tsa}}$ is a 128-bit cryptographically secure pseudorandom nonce.

### 3.4 Long-Term Timestamped Validity Invariant
A signed firmware payload remains cryptographically valid even if the verification timestamp $T_{\text{verify}} > T_{\text{cert,notAfter}}$, **if and only if** the verified RFC 3161 TimeStampToken generation time $T_{\text{TSA}}$ satisfies:

$$T_{\text{cert,notBefore}} \le T_{\text{TSA}} \le T_{\text{cert,notAfter}}$$

and the code-signing certificate was not revoked prior to $T_{\text{TSA}}$. If a timestamp is missing or falls outside this interval, verification fails.

---

## 4. 10-Rule Firmware Signing Security Posture Matrix

| Rule ID | Severity | Deduction | CWE | Rule Name & Posture Enforcement |
|:---|:---:|:---:|:---:|:---|
| **LH-FWS-001** | CRITICAL | -25 | CWE-327 | **Cryptographic Algorithm Modernity & Padding Invariant**: Mandates RSASSA-PSS and Ed25519; strictly prohibits PKCS#1 v1.5 padding and SHA-1/MD5; enforces RSA key length $\ge 3072$ bits. |
| **LH-FWS-002** | CRITICAL | -25 | CWE-522 | **PKCS#11 HSM Hardware Key Isolation & Non-Extractability Guard**: Requires private signing keys to be stored in FIPS 140-3 Level 3 HSMs with `CKA_SENSITIVE = true` and `CKA_EXTRACTABLE = false`. |
| **LH-FWS-003** | CRITICAL | -25 | CWE-347 | **RFC 3161 Cryptographic Timestamp & Code-Signing EKU Enforcement**: Mandates RFC 3161 TSA tokens and verifies X.509 `ExtKeyUsageCodeSigning` (`1.3.6.1.5.5.7.3.3`). |
| **LH-FWS-004** | HIGH | -10 | CWE-693 | **Anti-Rollback SVN & Hardware Target ID Cryptographic Binding**: Requires cryptographic binding of monotonic Security Version Number ($\text{SVN} \ge 1$) and canonical `HardwareCompatID`. |
| **LH-FWS-005** | HIGH | -10 | CWE-307 | **HSM PIN Ingestion Hygiene & Brute-Force Lockout Defense**: Prohibits passing HSM User PINs via CLI argv (preventing process table leaks) and enforces PIN lockout after $\le 5$ consecutive failures. |
| **LH-FWS-006** | HIGH | -10 | CWE-284 | **Dual-Custody M-of-N Multi-Party Approval Quorum Enforcement**: Requires M-of-N multi-party authorization quorum (minimum 2 approvers) for production firmware release ceremonies. |
| **LH-FWS-007** | HIGH | -10 | CWE-295 | **Certificate Revocation Checking & Maximum Validity Ceiling Guard**: Enforces real-time CRL/OCSP certificate revocation checks and restricts leaf certificate lifespan to $\le 397$ days. |
| **LH-FWS-008** | MEDIUM | -4 | CWE-330 | **RSASSA-PSS Salt Length Invariant & Dual-Algorithm Redundancy**: Mandates RSA-PSS salt length equal to hash length and requires hybrid Ed25519 + RSA-PSS signature redundancy. |
| **LH-FWS-009** | MEDIUM | -4 | CWE-226 | **HSM Ephemeral Session Teardown & Inactivity Timeout Guard**: Enforces immediate session logout post-signing and restricts session inactivity timeouts to $\le 60$ seconds. |
| **LH-FWS-010** | LOW | -1 | CWE-778 | **Append-Only Signing Transparency Log & Provenance Audit Trail**: Mandates publication of cryptographic signing receipts and build provenance hashes to an append-only transparency log. |

**Standardized Posture Scoring Model**:
$$S_{\text{posture}} = \max\left(0, 100 - \sum \text{Deductions}\right)$$
- `PASS`: $S_{\text{posture}} = 100$ (Exit Code `0`).
- `FAIL`: $S_{\text{posture}} < 100$ or any failed critical/high rule (Exit Code `1`).

---

## 5. CLI Usage & Command Reference

### 5.1 Audit Firmware Signing Posture (`scan`)
Audits release infrastructure policies against the 10-rule posture matrix:

```bash
# Terminal ANSI Table
lh-fw-sign scan fixtures/hardened_fwsign_policy.json --format table

# Canonical JSON
lh-fw-sign scan fixtures/hardened_fwsign_policy.json --format json

# OASIS SARIF v2.1.0 (for CI/CD and GitHub Security Tab)
lh-fw-sign scan fixtures/hardened_fwsign_policy.json --format sarif --output report.sarif
```

### 5.2 Sign Binary Firmware (`sign`)
Performs hybrid Ed25519 + RSA-PSS signing with PKCS#11 HSM session management and RFC 3161 TSA timestamping:

```bash
# Sign firmware and output SignedFirmwareReceipt JSON
lh-fw-sign sign \
  --firmware bootloader.bin \
  --svn 7 \
  --hw-id tegra234-orin-industrial \
  --output receipt.json

# Sign firmware and attach monolithic LHFWSIG1 binary trailer
lh-fw-sign sign \
  --firmware bootloader.bin \
  --svn 7 \
  --hw-id tegra234-orin-industrial \
  --output receipt.json \
  --attach-trailer
```

### 5.3 Cryptographic Verification (`verify`)
Validates image integrity, anti-rollback SVN, hardware ID, dual signatures, X.509 chains, and TSA tokens:

```bash
# Verify using standalone receipt JSON
lh-fw-sign verify \
  --firmware bootloader.bin \
  --receipt receipt.json \
  --min-svn 7 \
  --hw-id tegra234-orin-industrial

# Verify monolithic firmware with attached binary trailer (no separate receipt needed)
lh-fw-sign verify \
  --firmware bootloader.bin.signed \
  --min-svn 7 \
  --hw-id tegra234-orin-industrial
```

### 5.4 PKCS#11 HSM Diagnostics (`inspect-hsm`)
Simulates PKCS#11 session transitions, key attribute validations, and PIN lockout mechanics:

```bash
lh-fw-sign inspect-hsm --simulate-pin-lockout
```

### 5.5 Generate Code-Signing Certificate Pair (`gen-cert`)
Generates in-memory X.509 v3 Code-Signing Root CA and Leaf certificates:

```bash
lh-fw-sign gen-cert --days 365 --ca-out ca.pem --leaf-out leaf.pem
```

---

## 6. Build & Test Instructions

### 6.1 Prerequisites
Requires **Go 1.22+** (standard toolchain). No CGO or external libraries required.

```bash
# Verify code formatting
test -z "$(gofmt -s -l .)"

# Run static analysis
go vet ./...

# Execute full verification suite with race detector
go test -v -race ./...

# Compile CLI binary
go build -o bin/lh-fw-sign cmd/lh-fw-sign/main.go
```

---

## 7. Zero External Dependencies Guarantee

`lh-firmware-sign-cli` is implemented **exclusively with the Go Standard Library**:
- `crypto/ed25519`, `crypto/rsa`, `crypto/rand`, `crypto/sha256`, `crypto/sha512`
- `crypto/x509`, `crypto/x509/pkix`, `encoding/pem`, `math/big`
- `encoding/binary`, `encoding/hex`, `encoding/json`
- `os`, `sync`, `time`, `fmt`, `strings`

`go.mod` contains **zero `require` directives**, guaranteeing zero supply-chain risk, instant offline reproducible compilation, and complete immunity to upstream dependency vulnerabilities.

---

## 8. Governance & Maintainers

- **Author**: Sameer Tawade (`ops@logihertz.com` / `security@logihertz.com`)
- **Organization**: Logihertz Systems (OPC) Private Limited (`https://logihertz.com/`)
- **License**: Apache License, Version 2.0 (see [LICENSE](LICENSE))
- **Security Policy**: See [SECURITY.md](SECURITY.md)
- **Contributing Guidelines**: See [CONTRIBUTING.md](CONTRIBUTING.md)
