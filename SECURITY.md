# Security Policy: lh-firmware-sign-cli

Logihertz Systems (OPC) Private Limited maintains high-assurance security standards for embedded firmware integrity, secure boot provenance, and cryptographic signing infrastructure.

## Supported Versions

| Version | Supported          | Security Maintenance Status |
|---------|--------------------|-----------------------------|
| 0.1.x   | :white_check_mark: | Active Current Release      |
| < 0.1.0 | :x:                | Unsupported                 |

## Threat Model & Scope

The `lh-firmware-sign-cli` (`lh-fw-sign`) CLI and library enforce cryptographic code-signing and posture auditing for sovereign embedded systems, industrial controllers, and edge AI compute modules. Key threat vectors addressed include:

- **Hardware Security Module (HSM) Key Isolation**: Enforcing PKCS#11 v3.0 `CKA_SENSITIVE = true` and `CKA_EXTRACTABLE = false` invariants. Signing keys must never be resident in plaintext on host filesystems or exposed in user-space core dumps.
- **PIN Brute-Force & Lockout Defenses**: Rigorously tracking PIN verification attempts; latching `CKR_PIN_LOCKED` after reaching the maximum threshold (default 3 retries) and prohibiting CLI command-line argument PIN ingestion.
- **Dual/Hybrid Cryptography Resistance**: Combining RFC 8032 Ed25519 with RFC 8017 RSA-PSS-SHA384 redundancy to resist single-algorithm cryptographic breaks and algorithm confusion attacks.
- **Firmware Anti-Rollback & Cross-Board Flashing**: Binding strictly monotonic Security Version Numbers (`SVN`) and canonical `HardwareCompatID` into authenticated headers (`FirmwareHeaderV1`) prior to signature generation.
- **Long-Term Verification via RFC 3161 TSA**: Requiring cryptographic Time-Stamp Authority tokens to bind signatures to active certificate validity windows, preventing malicious exploitation of compromised or expired private keys after signing ceremonies.

## Reporting a Vulnerability

If you identify a security issue, vulnerability, or cryptographic weakness in `lh-firmware-sign-cli`, please report it promptly to:

- **Primary Contact**: Sameer Tawade (`security@logihertz.com`)
- **Operations Team**: `ops@logihertz.com`
- **PGP Encryption**: Available upon request for sensitive reports.
- **Report Details Required**:
  - Detailed description and threat impact assessment
  - Affected components (`pkg/fwsign`, `HsmTokenSession`, `TimeStampToken`, etc.)
  - Reproduction receipt, binary payload, or policy configuration
  - Remediation proposal if available

## Response Timeline

- **Initial Acknowledgement**: Within 24 business hours.
- **Triage & Severity Assessment**: Within 72 business hours.
- **Remediation & Advisory Release**: Coordinated disclosure within 30 calendar days.
