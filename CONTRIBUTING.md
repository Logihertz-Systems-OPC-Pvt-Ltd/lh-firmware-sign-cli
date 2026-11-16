# Contributing to Logihertz Firmware Signer CLI (`lh-firmware-sign-cli`)

Thank you for contributing to **`lh-firmware-sign-cli`** (`lh-fw-sign`)! We maintain strict cryptographic rigor, zero external supply-chain dependencies, and reproducible builds.

## Architectural Mandates

1. **100% Zero External Dependencies**:
   - `go.mod` must never include an external `require` block.
   - All cryptographic primitives, X.509 chains, PKCS#11 session machines, and JSON/SARIF formatters must be implemented strictly via the Go Standard Library (`crypto`, `encoding`, `math/big`, etc.).
2. **Cryptographic Standards**:
   - Dual/hybrid signing must pair RFC 8032 Ed25519 with RFC 8017 RSASSA-PSS (minimum 3072-bit keys with SHA-384 and salt length equal to hash length).
   - Time-Stamp Tokens must adhere to RFC 3161 message imprint semantics (`SHA-256(LH_RFC3161_IMPRINT: || sig || digest || nonce)`).
   - PKCS#11 states must strictly observe OASIS PKCS#11 v3.0 lifecycle semantics.
3. **Deterministic Testing**:
   - Every feature must be backed by deterministic unit tests without flaky network or wall-clock dependencies.
   - All tests must pass with `go test -v -race ./...`.

## Development & Verification Workflow

```bash
# Verify formatting
test -z "$(gofmt -s -l .)"

# Static analysis
go vet ./...

# Race-detector test execution
go test -v -race ./...

# Build binary
go build -o bin/lh-fw-sign cmd/lh-fw-sign/main.go
```

## Commit Conventions

We follow Conventional Commits:
- `feat(signer): add support for ed25519-ph prehashed signing`
- `fix(pkcs11): correct CKR_PIN_LOCKED transition counter`
- `test(auditor): add test cases for LH-FWS-005 argv PIN leak`

## Code of Conduct

All contributors are expected to uphold the standards defined in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
